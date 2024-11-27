/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.resources;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.Callable;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;

import org.opensearch.accesscontrol.resources.*;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.*;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.*;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.search.Scroll;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

public class ResourceSharingIndexHandler {

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Client client;

    private final String resourceSharingIndex;

    private final ThreadPool threadPool;

    public ResourceSharingIndexHandler(final String indexName, final Client client, ThreadPool threadPool) {
        this.resourceSharingIndex = indexName;
        this.client = client;
        this.threadPool = threadPool;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    /**
     * Creates the resource sharing index if it doesn't already exist.
     * This method initializes the index with predefined mappings and settings
     * for storing resource sharing information.
     * The index will be created with the following structure:
     * - source_idx (keyword): The source index containing the original document
     * - resource_id (keyword): The ID of the shared resource
     * - created_by (object): Information about the user who created the sharing
     *   - user (keyword): Username of the creator
     * - share_with (object): Access control configuration for shared resources
     *   - [group_name] (object): Name of the access group
     *     - users (array): List of users with access
     *     - roles (array): List of roles with access
     *     - backend_roles (array): List of backend roles with access
     *
     * @throws RuntimeException if there are issues reading/writing index settings
     *                    or communicating with the cluster
     */

    public void createResourceSharingIndexIfAbsent(Callable<Boolean> callable) {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            CreateIndexRequest cir = new CreateIndexRequest(resourceSharingIndex).settings(INDEX_SETTINGS).waitForActiveShards(1);
            ActionListener<CreateIndexResponse> cirListener = ActionListener.wrap(response -> {
                LOGGER.info("Resource sharing index {} created.", resourceSharingIndex);
                callable.call();
            }, (failResponse) -> {
                /* Index already exists, ignore and continue */
                LOGGER.info("Index {} already exists.", resourceSharingIndex);
                try {
                    callable.call();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            this.client.admin().indices().create(cir, cirListener);
        }
    }

    /**
     * Creates or updates a resource sharing record in the dedicated resource sharing index.
     * This method handles the persistence of sharing metadata for resources, including
     * the creator information and sharing permissions.
     *
     * @param resourceId The unique identifier of the resource being shared
     * @param resourceIndex The source index where the original resource is stored
     * @param createdBy Object containing information about the user creating/updating the sharing
     * @param shareWith Object containing the sharing permissions' configuration. Can be null for initial creation.
     *                 When provided, it should contain the access control settings for different groups:
     *                 {
     *                     "group_name": {
     *                         "users": ["user1", "user2"],
     *                         "roles": ["role1", "role2"],
     *                         "backend_roles": ["backend_role1"]
     *                     }
     *                 }
     *
     * @return ResourceSharing Returns resourceSharing object if the operation was successful, null otherwise
     * @throws IOException if there are issues with index operations or JSON processing
     */

    public ResourceSharing indexResourceSharing(String resourceId, String resourceIndex, CreatedBy createdBy, ShareWith shareWith)
        throws IOException {

        try {
            ResourceSharing entry = new ResourceSharing(resourceIndex, resourceId, createdBy, shareWith);

            IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(entry.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .request();

            LOGGER.info("Index Request: {}", ir.toString());

            ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                LOGGER.info("Successfully created {} entry.", resourceSharingIndex);
            }, (failResponse) -> {
                LOGGER.error(failResponse.getMessage());
                LOGGER.info("Failed to create {} entry.", resourceSharingIndex);
            });
            client.index(ir, irListener);
            return entry;
        } catch (Exception e) {
            LOGGER.info("Failed to create {} entry.", resourceSharingIndex, e);
            return null;
        }
    }

    /**
        * Fetches all resource sharing records that match the specified system index. This method retrieves
        * a list of resource IDs associated with the given system index from the resource sharing index.
        *
        * <p>The method executes the following steps:
        * <ol>
        *   <li>Creates a search request with term query matching the system index</li>
        *   <li>Applies source filtering to only fetch resource_id field</li>
        *   <li>Executes the search with a limit of 10000 documents</li>
        *   <li>Processes the results to extract resource IDs</li>
        * </ol>
        *
        * <p>Example query structure:
        * <pre>
        * {
        *   "query": {
        *     "term": {
        *       "source_idx": "system_index_name"
        *     }
        *   },
        *   "_source": ["resource_id"],
        *   "size": 10000
        * }
        * </pre>
        *
        * @param pluginIndex The source index to match against the source_idx field
        * @return List<String> containing resource IDs that belong to the specified system index.
        *         Returns an empty list if:
        *         <ul>
        *           <li>No matching documents are found</li>
        *           <li>An error occurs during the search operation</li>
        *           <li>The system index parameter is invalid</li>
        *         </ul>
        *
        * @apiNote This method:
        * <ul>
        *   <li>Uses source filtering for optimal performance</li>
        *   <li>Performs exact matching on the source_idx field</li>
        *   <li>Returns an empty list instead of throwing exceptions</li>
        * </ul>
        */
    public List<String> fetchAllDocuments(String pluginIndex) {
        LOGGER.debug("Fetching all documents from {} where source_idx = {}", resourceSharingIndex, pluginIndex);

        try {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.termQuery("source_idx", pluginIndex));
            searchSourceBuilder.size(10000); // TODO check what size should be set here.

            searchSourceBuilder.fetchSource(new String[] { "resource_id" }, null);

            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = client.search(searchRequest).actionGet();

            List<String> resourceIds = new ArrayList<>();

            SearchHit[] hits = searchResponse.getHits().getHits();
            for (SearchHit hit : hits) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                if (sourceAsMap != null && sourceAsMap.containsKey("resource_id")) {
                    resourceIds.add(sourceAsMap.get("resource_id").toString());
                }
            }

            LOGGER.debug("Found {} documents in {} for source_idx: {}", resourceIds.size(), resourceSharingIndex, pluginIndex);

            return resourceIds;

        } catch (Exception e) {
            LOGGER.error("Failed to fetch documents from {} for source_idx: {}", resourceSharingIndex, pluginIndex, e);
            return List.of();
        }
    }

    /**
    * Fetches documents that match the specified system index and have specific access type values.
    * This method uses scroll API to handle large result sets efficiently.
    *
    * <p>The method executes the following steps:
    * <ol>
    *   <li>Validates the entityType parameter</li>
    *   <li>Creates a scrolling search request with a compound query</li>
    *   <li>Processes results in batches using scroll API</li>
    *   <li>Collects all matching resource IDs</li>
    *   <li>Cleans up scroll context</li>
    * </ol>
    *
    * <p>Example query structure:
    * <pre>
    * {
    *   "query": {
    *     "bool": {
    *       "must": [
    *         { "term": { "source_idx": "system_index_name" } },
    *         {
    *           "bool": {
    *             "should": [
    *               {
    *                 "nested": {
    *                   "path": "share_with.*.entityType",
    *                   "query": {
    *                     "term": { "share_with.*.entityType": "entity_value" }
    *                   }
    *                 }
    *               }
    *             ],
    *             "minimum_should_match": 1
    *           }
    *         }
    *       ]
    *     }
    *   },
    *   "_source": ["resource_id"],
    *   "size": 1000
    * }
    * </pre>
    *
    * @param pluginIndex The source index to match against the source_idx field
    * @param entities Set of values to match in the specified entityType field
    * @param entityType The type of association with the resource. Must be one of:
    *                  <ul>
    *                    <li>"users" - for user-based access</li>
    *                    <li>"roles" - for role-based access</li>
    *                    <li>"backend_roles" - for backend role-based access</li>
    *                  </ul>
    * @return List<String> List of resource IDs that match the criteria. The list may be empty
    *         if no matches are found
    *
    * @throws RuntimeException if the search operation fails
    *
    * @apiNote This method:
    * <ul>
    *   <li>Uses scroll API with 1-minute timeout</li>
    *   <li>Processes results in batches of 1000 documents</li>
    *   <li>Performs source filtering for optimization</li>
    *   <li>Uses nested queries for accessing array elements</li>
    *   <li>Properly cleans up scroll context after use</li>
    * </ul>
    */

    public List<String> fetchDocumentsForAllScopes(String pluginIndex, Set<String> entities, String entityType) {
        LOGGER.debug("Fetching documents from index: {}, where share_with.*.{} contains any of {}", pluginIndex, entityType, entities);

        List<String> resourceIds = new ArrayList<>();
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery().must(QueryBuilders.termQuery("source_idx", pluginIndex));

            BoolQueryBuilder shouldQuery = QueryBuilders.boolQuery();
            for (String entity : entities) {
                shouldQuery.should(
                    QueryBuilders.nestedQuery(
                        "share_with.*." + entityType,
                        QueryBuilders.termQuery("share_with.*." + entityType, entity),
                        ScoreMode.None
                    )
                );
            }
            shouldQuery.minimumShouldMatch(1);
            boolQuery.must(shouldQuery);

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQuery)
                .size(1000)
                .fetchSource(new String[] { "resource_id" }, null);

            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = client.search(searchRequest).actionGet();
            String scrollId = searchResponse.getScrollId();
            SearchHit[] hits = searchResponse.getHits().getHits();

            while (hits != null && hits.length > 0) {
                for (SearchHit hit : hits) {
                    Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                    if (sourceAsMap != null && sourceAsMap.containsKey("resource_id")) {
                        resourceIds.add(sourceAsMap.get("resource_id").toString());
                    }
                }

                SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
                scrollRequest.scroll(scroll);
                searchResponse = client.execute(SearchScrollAction.INSTANCE, scrollRequest).actionGet();
                scrollId = searchResponse.getScrollId();
                hits = searchResponse.getHits().getHits();
            }

            ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
            clearScrollRequest.addScrollId(scrollId);
            client.clearScroll(clearScrollRequest).actionGet();

            LOGGER.debug("Found {} documents matching the criteria in {}", resourceIds.size(), resourceSharingIndex);

            return resourceIds;

        } catch (Exception e) {
            LOGGER.error(
                "Failed to fetch documents from {} for criteria - systemIndex: {}, shareWithType: {}, accessWays: {}",
                resourceSharingIndex,
                pluginIndex,
                entityType,
                entities,
                e
            );
            throw new RuntimeException("Failed to fetch documents: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches documents from the resource sharing index that match a specific field value.
     * This method uses scroll API to efficiently handle large result sets and performs exact
     * matching on both system index and the specified field.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Validates input parameters for null/empty values</li>
     *   <li>Creates a scrolling search request with a bool query</li>
     *   <li>Processes results in batches using scroll API</li>
     *   <li>Extracts resource IDs from matching documents</li>
     *   <li>Cleans up scroll context after completion</li>
     * </ol>
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": "system_index_value" } },
     *         { "term": { "field_name": "field_value" } }
     *       ]
     *     }
     *   },
     *   "_source": ["resource_id"],
     *   "size": 1000
     * }
     * </pre>
     *
     * @param systemIndex The source index to match against the source_idx field
     * @param field The field name to search in. Must be a valid field in the index mapping
     * @param value The value to match for the specified field. Performs exact term matching
     * @return List<String> List of resource IDs that match the criteria. Returns an empty list
     *         if no matches are found
     *
     * @throws IllegalArgumentException if any parameter is null or empty
     * @throws RuntimeException if the search operation fails, wrapping the underlying exception
     *
     * @apiNote This method:
     * <ul>
     *   <li>Uses scroll API with 1-minute timeout for handling large result sets</li>
     *   <li>Performs exact term matching (not analyzed) on field values</li>
     *   <li>Processes results in batches of 1000 documents</li>
     *   <li>Uses source filtering to only fetch resource_id field</li>
     *   <li>Automatically cleans up scroll context after use</li>
     * </ul>
     *
     * Example usage:
     * <pre>
     * List<String> resources = fetchDocumentsByField("myIndex", "status", "active");
     * </pre>
     */

    public List<String> fetchDocumentsByField(String systemIndex, String field, String value) {
        if (StringUtils.isBlank(systemIndex) || StringUtils.isBlank(field) || StringUtils.isBlank(value)) {
            throw new IllegalArgumentException("systemIndex, field, and value must not be null or empty");
        }

        LOGGER.debug("Fetching documents from index: {}, where {} = {}", systemIndex, field, value);

        List<String> resourceIds = new ArrayList<>();
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try {
            // Create initial search request
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            // Build the query
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx", systemIndex))
                .must(QueryBuilders.termQuery(field, value));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQuery)
                .size(1000)
                .fetchSource(new String[] { "resource_id" }, null);

            searchRequest.source(searchSourceBuilder);

            // Execute initial search
            SearchResponse searchResponse = client.search(searchRequest).actionGet();
            String scrollId = searchResponse.getScrollId();
            SearchHit[] hits = searchResponse.getHits().getHits();

            // Process results in batches
            while (hits != null && hits.length > 0) {
                for (SearchHit hit : hits) {
                    Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                    if (sourceAsMap != null && sourceAsMap.containsKey("resource_id")) {
                        resourceIds.add(sourceAsMap.get("resource_id").toString());
                    }
                }

                SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
                scrollRequest.scroll(scroll);
                searchResponse = client.execute(SearchScrollAction.INSTANCE, scrollRequest).actionGet();
                scrollId = searchResponse.getScrollId();
                hits = searchResponse.getHits().getHits();
            }

            // Clear scroll
            ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
            clearScrollRequest.addScrollId(scrollId);
            client.clearScroll(clearScrollRequest).actionGet();

            LOGGER.debug("Found {} documents in {} where {} = {}", resourceIds.size(), resourceSharingIndex, field, value);

            return resourceIds;

        } catch (Exception e) {
            LOGGER.error("Failed to fetch documents from {} where {} = {}", resourceSharingIndex, field, value, e);
            throw new RuntimeException("Failed to fetch documents: " + e.getMessage(), e);
        }
    }

    /**
    * Fetches a specific resource sharing document by its resource ID and system index.
    * This method performs an exact match search and parses the result into a ResourceSharing object.
    *
    * <p>The method executes the following steps:
    * <ol>
    *   <li>Validates input parameters for null/empty values</li>
    *   <li>Creates a search request with a bool query for exact matching</li>
    *   <li>Executes the search with a limit of 1 document</li>
    *   <li>Parses the result using XContent parser if found</li>
    *   <li>Returns null if no matching document exists</li>
    * </ol>
    *
    * <p>Example query structure:
    * <pre>
    * {
    *   "query": {
    *     "bool": {
    *       "must": [
    *         { "term": { "source_idx": "system_index_name" } },
    *         { "term": { "resource_id": "resource_id_value" } }
    *       ]
    *     }
    *   },
    *   "size": 1
    * }
    * </pre>
    *
    * @param pluginIndex The source index to match against the source_idx field
    * @param resourceId The resource ID to fetch. Must exactly match the resource_id field
    * @return ResourceSharing object if a matching document is found, null if no document
    *         matches the criteria
    *
    * @throws IllegalArgumentException if systemIndexName or resourceId is null or empty
    * @throws RuntimeException if the search operation fails or parsing errors occur,
    *         wrapping the underlying exception
    *
    * @apiNote This method:
    * <ul>
    *   <li>Uses term queries for exact matching</li>
    *   <li>Expects only one matching document per resource ID</li>
    *   <li>Uses XContent parsing for consistent object creation</li>
    *   <li>Returns null instead of throwing exceptions for non-existent documents</li>
    *   <li>Provides detailed logging for troubleshooting</li>
    * </ul>
    *
    * Example usage:
    * <pre>
    * ResourceSharing sharing = fetchDocumentById("myIndex", "resource123");
    * if (sharing != null) {
    *     // Process the resource sharing object
    * }
    * </pre>
    */

    public ResourceSharing fetchDocumentById(String pluginIndex, String resourceId) {
        // Input validation
        if (StringUtils.isBlank(pluginIndex) || StringUtils.isBlank(resourceId)) {
            throw new IllegalArgumentException("systemIndexName and resourceId must not be null or empty");
        }

        LOGGER.debug("Fetching document from index: {}, with resourceId: {}", pluginIndex, resourceId);

        try {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx", pluginIndex))
                .must(QueryBuilders.termQuery("resource_id", resourceId));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQuery).size(1); // We only need one document since
                                                                                                          // a resource must have only one
                                                                                                          // sharing entry

            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = client.search(searchRequest).actionGet();

            SearchHit[] hits = searchResponse.getHits().getHits();
            if (hits.length == 0) {
                LOGGER.debug("No document found for resourceId: {} in index: {}", resourceId, pluginIndex);
                return null;
            }

            SearchHit hit = hits[0];
            try (
                XContentParser parser = XContentType.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString())
            ) {

                parser.nextToken();

                ResourceSharing resourceSharing = ResourceSharing.fromXContent(parser);

                LOGGER.debug("Successfully fetched document for resourceId: {} from index: {}", resourceId, pluginIndex);

                return resourceSharing;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to fetch document for resourceId: {} from index: {}", resourceId, pluginIndex, e);
            throw new RuntimeException("Failed to fetch document: " + e.getMessage(), e);
        }
    }

    /**
     * Updates resource sharing entries that match the specified source index and resource ID
     * using the provided update script. This method performs an update-by-query operation
     * in the resource sharing index.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Creates a bool query to match exact source index and resource ID</li>
     *   <li>Constructs an update-by-query request with the query and update script</li>
     *   <li>Executes the update operation</li>
     *   <li>Returns success/failure status based on update results</li>
     * </ol>
     *
     * <p>Example document matching structure:
     * <pre>
     * {
     *   "source_idx": "source_index_name",
     *   "resource_id": "resource_id_value",
     *   "share_with": {
     *     // sharing configuration to be updated
     *   }
     * }
     * </pre>
     *
     * @param sourceIdx The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @param updateScript The script containing the update operations to be performed.
     *                    This script defines how the matching documents should be modified
     * @return boolean true if at least one document was updated, false if no documents
     *         were found or update failed
     *
     * @apiNote This method:
     * <ul>
     *   <li>Uses term queries for exact matching of source_idx and resource_id</li>
     *   <li>Returns false for both "no matching documents" and "operation failure" cases</li>
     *   <li>Logs the complete update request for debugging purposes</li>
     *   <li>Provides detailed logging for success and failure scenarios</li>
     * </ul>
     *
     * @implNote The update operation uses a bool query with two must clauses:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": sourceIdx } },
     *         { "term": { "resource_id": resourceId } }
     *       ]
     *     }
     *   }
     * }
     * </pre>
     */
    private boolean updateByQueryResourceSharing(String sourceIdx, String resourceId, Script updateScript) {
        try {
            // Create a bool query to match both fields
            BoolQueryBuilder query = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx", sourceIdx))
                .must(QueryBuilders.termQuery("resource_id", resourceId));

            UpdateByQueryRequest ubq = new UpdateByQueryRequest(resourceSharingIndex).setQuery(query).setScript(updateScript);

            LOGGER.info("Update By Query Request: {}", ubq.toString());

            BulkByScrollResponse response = client.execute(UpdateByQueryAction.INSTANCE, ubq).actionGet();

            if (response.getUpdated() > 0) {
                LOGGER.info("Successfully updated {} documents in {}.", response.getUpdated(), resourceSharingIndex);
                return true;
            } else {
                LOGGER.info(
                    "No documents found to update in {} for source_idx: {} and resource_id: {}",
                    resourceSharingIndex,
                    sourceIdx,
                    resourceId
                );
                return false;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to update documents in {}.", resourceSharingIndex, e);
            return false;
        }
    }

    /**
     * Updates the sharing configuration for an existing resource in the resource sharing index.
     * This method modifies the sharing permissions for a specific resource identified by its
     * resource ID and source index.
     *
     * @param resourceId The unique identifier of the resource whose sharing configuration needs to be updated
     * @param sourceIdx The source index where the original resource is stored
     * @param shareWith Updated sharing configuration object containing access control settings:
     *                 {
     *                     "scope": {
     *                         "users": ["user1", "user2"],
     *                         "roles": ["role1", "role2"],
     *                         "backend_roles": ["backend_role1"]
     *                     }
     *                 }
     * @return ResourceSharing Returns resourceSharing object if the update was successful, null otherwise
     * @throws RuntimeException if there's an error during the update operation
     */
    public ResourceSharing updateResourceSharingInfo(String resourceId, String sourceIdx, CreatedBy createdBy, ShareWith shareWith) {
        Script updateScript = new Script(
            ScriptType.INLINE,
            "painless",
            "ctx._source.shareWith = params.newShareWith",
            Collections.singletonMap("newShareWith", shareWith)
        );

        boolean success = updateByQueryResourceSharing(sourceIdx, resourceId, updateScript);
        return success ? new ResourceSharing(resourceId, sourceIdx, createdBy, shareWith) : null;
    }

    /**
     * Revokes access for specified entities from a resource sharing document. This method removes the specified
     * entities (users, roles, or backend roles) from the existing sharing configuration while preserving other
     * sharing settings.
     *
     * <p>The method performs the following steps:
     * <ol>
     *   <li>Fetches the existing document</li>
     *   <li>Removes specified entities from their respective lists in all sharing groups</li>
     *   <li>Updates the document if modifications were made</li>
     *   <li>Returns the updated resource sharing configuration</li>
     * </ol>
     *
     * <p>Example document structure:
     * <pre>
     * {
     *   "source_idx": "system_index_name",
     *   "resource_id": "resource_id",
     *   "share_with": {
     *     "group_name": {
     *       "users": ["user1", "user2"],
     *       "roles": ["role1", "role2"],
     *       "backend_roles": ["backend_role1"]
     *     }
     *   }
     * }
     * </pre>
     *
     * @param resourceId The ID of the resource from which to revoke access
     * @param systemIndexName The name of the system index where the resource exists
     * @param revokeAccess A map containing entity types (USER, ROLE, BACKEND_ROLE) and their corresponding
     *                     values to be removed from the sharing configuration
     * @return The updated ResourceSharing object after revoking access, or null if the document doesn't exist
     * @throws IllegalArgumentException if resourceId, systemIndexName is null/empty, or if revokeAccess is null/empty
     * @throws RuntimeException if the update operation fails or encounters an error
     *
     * @see EntityType
     * @see ResourceSharing
     *
     * @apiNote This method modifies the existing document. If no modifications are needed (i.e., specified
     *          entities don't exist in the current configuration), the original document is returned unchanged.
     * &#064;example
     * <pre>
     * Map<EntityType, List<String>> revokeAccess = new HashMap<>();
     * revokeAccess.put(EntityType.USER, Arrays.asList("user1", "user2"));
     * revokeAccess.put(EntityType.ROLE, Arrays.asList("role1"));
     * ResourceSharing updated = revokeAccess("resourceId", "systemIndex", revokeAccess);
     * </pre>
     */

    public ResourceSharing revokeAccess(String resourceId, String systemIndexName, Map<EntityType, List<String>> revokeAccess) {
        // TODO; check if this needs to be done per scope rather than for all scopes

        // Input validation
        if (StringUtils.isBlank(resourceId) || StringUtils.isBlank(systemIndexName) || revokeAccess == null || revokeAccess.isEmpty()) {
            throw new IllegalArgumentException("resourceId, systemIndexName, and revokeAccess must not be null or empty");
        }

        LOGGER.debug("Revoking access for resource {} in {} for entities: {}", resourceId, systemIndexName, revokeAccess);

        try {
            // First fetch the existing document
            ResourceSharing existingResource = fetchDocumentById(systemIndexName, resourceId);
            if (existingResource == null) {
                LOGGER.warn("No document found for resourceId: {} in index: {}", resourceId, systemIndexName);
                return null;
            }

            ShareWith shareWith = existingResource.getShareWith();
            boolean modified = false;

            if (shareWith != null) {
                for (SharedWithScope sharedWithScope : shareWith.getSharedWithScopes()) {
                    SharedWithScope.SharedWithPerScope sharedWithPerScope = sharedWithScope.getSharedWithPerScope();

                    for (Map.Entry<EntityType, List<String>> entry : revokeAccess.entrySet()) {
                        EntityType entityType = entry.getKey();
                        List<String> entities = entry.getValue();

                        // Check if the entity type exists in the share_with configuration
                        switch (entityType) {
                            case USERS:
                                if (sharedWithPerScope.getUsers() != null) {
                                    modified = sharedWithPerScope.getUsers().removeAll(entities) || modified;
                                }
                                break;
                            case ROLES:
                                if (sharedWithPerScope.getRoles() != null) {
                                    modified = sharedWithPerScope.getRoles().removeAll(entities) || modified;
                                }
                                break;
                            case BACKEND_ROLES:
                                if (sharedWithPerScope.getBackendRoles() != null) {
                                    modified = sharedWithPerScope.getBackendRoles().removeAll(entities) || modified;
                                }
                                break;
                        }
                    }
                }
            }

            if (!modified) {
                LOGGER.debug("No modifications needed for resource: {}", resourceId);
                return existingResource;
            }

            // Update resource sharing info
            return updateResourceSharingInfo(resourceId, systemIndexName, existingResource.getCreatedBy(), shareWith);

        } catch (Exception e) {
            LOGGER.error("Failed to revoke access for resource: {} in index: {}", resourceId, systemIndexName, e);
            throw new RuntimeException("Failed to revoke access: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes resource sharing records that match the specified source index and resource ID.
     * This method performs a delete-by-query operation in the resource sharing index.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Creates a delete-by-query request with a bool query</li>
     *   <li>Matches documents based on exact source index and resource ID</li>
     *   <li>Executes the delete operation with immediate refresh</li>
     *   <li>Returns the success/failure status based on deletion results</li>
     * </ol>
     *
     * <p>Example document structure that will be deleted:
     * <pre>
     * {
     *   "source_idx": "source_index_name",
     *   "resource_id": "resource_id_value",
     *   "share_with": {
     *     // sharing configuration
     *   }
     * }
     * </pre>
     *
     * @param sourceIdx The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @return boolean true if at least one document was deleted, false if no documents were found or deletion failed
     *
     * @implNote The delete operation uses a bool query with two must clauses to ensure exact matching:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": sourceIdx } },
     *         { "term": { "resource_id": resourceId } }
     *       ]
     *     }
     *   }
     * }
     * </pre>
     */
    public boolean deleteResourceSharingRecord(String resourceId, String sourceIdx) {
        LOGGER.info("Deleting documents from {} where source_idx = {} and resource_id = {}", resourceSharingIndex, sourceIdx, resourceId);

        try {
            DeleteByQueryRequest dbq = new DeleteByQueryRequest(resourceSharingIndex).setQuery(
                QueryBuilders.boolQuery()
                    .must(QueryBuilders.termQuery("source_idx", sourceIdx))
                    .must(QueryBuilders.termQuery("resource_id", resourceId))
            ).setRefresh(true);

            BulkByScrollResponse response = client.execute(DeleteByQueryAction.INSTANCE, dbq).actionGet();

            if (response.getDeleted() > 0) {
                LOGGER.info("Successfully deleted {} documents from {}", response.getDeleted(), resourceSharingIndex);
                return true;
            } else {
                LOGGER.info(
                    "No documents found to delete in {} for source_idx: {} and resource_id: {}",
                    resourceSharingIndex,
                    sourceIdx,
                    resourceId
                );
                return false;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to delete documents from {}", resourceSharingIndex, e);
            return false;
        }
    }

    /**
        * Deletes all resource sharing records that were created by a specific user.
        * This method performs a delete-by-query operation to remove all documents where
        * the created_by.user field matches the specified username.
        *
        * <p>The method executes the following steps:
        * <ol>
        *   <li>Validates the input username parameter</li>
        *   <li>Creates a delete-by-query request with term query matching</li>
        *   <li>Executes the delete operation with immediate refresh</li>
        *   <li>Returns the operation status based on number of deleted documents</li>
        * </ol>
        *
        * <p>Example query structure:
        * <pre>
        * {
        *   "query": {
        *     "term": {
        *       "created_by.user": "username"
        *     }
        *   }
        * }
        * </pre>
        *
        * @param name The username to match against the created_by.user field
        * @return boolean indicating whether the deletion was successful:
        *         <ul>
        *           <li>true - if one or more documents were deleted</li>
        *           <li>false - if no documents were found</li>
        *           <li>false - if the operation failed due to an error</li>
        *         </ul>
        *
        * @throws IllegalArgumentException if name is null or empty
        *
        *
        * @implNote Implementation details:
        * <ul>
        *   <li>Uses DeleteByQueryRequest for efficient bulk deletion</li>
        *   <li>Sets refresh=true for immediate consistency</li>
        *   <li>Uses term query for exact username matching</li>
        *   <li>Implements comprehensive error handling and logging</li>
        * </ul>
        *
        * Example usage:
        * <pre>
        * boolean success = deleteAllRecordsForUser("john.doe");
        * if (success) {
        *     // Records were successfully deleted
        * } else {
        *     // No matching records found or operation failed
        * }
        * </pre>
        */
    public boolean deleteAllRecordsForUser(String name) {
        // Input validation
        if (StringUtils.isBlank(name)) {
            throw new IllegalArgumentException("Username must not be null or empty");
        }

        LOGGER.info("Deleting all records for user {}", name);

        try {
            DeleteByQueryRequest deleteRequest = new DeleteByQueryRequest(resourceSharingIndex).setQuery(
                QueryBuilders.termQuery("created_by.user", name)
            ).setRefresh(true);

            BulkByScrollResponse response = client.execute(DeleteByQueryAction.INSTANCE, deleteRequest).actionGet();

            long deletedDocs = response.getDeleted();

            if (deletedDocs > 0) {
                LOGGER.info("Successfully deleted {} documents created by user {}", deletedDocs, name);
                return true;
            } else {
                LOGGER.info("No documents found for user {}", name);
                return false;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to delete documents for user {}", name, e);
            return false;
        }
    }

}
