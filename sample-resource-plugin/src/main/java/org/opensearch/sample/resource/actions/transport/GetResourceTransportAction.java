/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.SampleResourceScope;
import org.opensearch.sample.resource.actions.rest.get.GetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceRequest;
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.client.resources.ResourceSharingClient;
import org.opensearch.security.common.support.ConfigConstants;
import org.opensearch.security.spi.resources.exceptions.ResourceSharingException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for getting a resource
 */
public class GetResourceTransportAction extends HandledTransportAction<GetResourceRequest, GetResourceResponse> {
    private static final Logger log = LogManager.getLogger(GetResourceTransportAction.class);

    private final TransportService transportService;
    private final NodeClient nodeClient;
    private final Settings settings;

    @Inject
    public GetResourceTransportAction(
        Settings settings,
        TransportService transportService,
        ActionFilters actionFilters,
        NodeClient nodeClient
    ) {
        super(GetResourceAction.NAME, transportService, actionFilters, GetResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
        this.settings = settings;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(Task task, GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient, settings);
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            // get all request
            if (this.settings.getAsBoolean(
                ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
                ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
            )) {
                resourceSharingClient.listAllAccessibleResources(RESOURCE_INDEX_NAME, ActionListener.wrap(resources -> {
                    listener.onResponse(new GetResourceResponse((Set<SampleResource>) resources));
                }, failure -> {
                    if (failure instanceof ResourceSharingException) {
                        if (((ResourceSharingException) failure).status().equals(RestStatus.NOT_IMPLEMENTED)) {
                            getAllResourcesAction(listener);
                            return;
                        }
                    }
                    listener.onFailure(failure);
                }));
            } else {
                // if feature is disabled, return all resources
                getAllResourcesAction(listener);
            }
            return;
        }

        // Check permission to resource
        resourceSharingClient.verifyResourceAccess(
            request.getResourceId(),
            RESOURCE_INDEX_NAME,
            Set.of(
                SampleResourceScope.SAMPLE_READ_ACCESS.value(),
                SampleResourceScope.SAMPLE_FULL_ACCESS.value(),
                SampleResourceScope.PUBLIC.value()
            ),
            ActionListener.wrap(isAuthorized -> {
                if (!isAuthorized) {
                    listener.onFailure(
                        new ResourceSharingException("Current user is not authorized to access resource: " + request.getResourceId())
                    );
                    return;
                }

                getResourceAction(request, listener);
            }, listener::onFailure)
        );
    }

    private void getResourceAction(GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            getResource(request, ActionListener.wrap(getResponse -> {
                if (getResponse.isSourceEmpty()) {
                    listener.onFailure(new ResourceNotFoundException("Resource " + request.getResourceId() + " not found."));
                } else {
                    try (
                        XContentParser parser = XContentType.JSON.xContent()
                            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, getResponse.getSourceAsString())
                    ) {
                        listener.onResponse(new GetResourceResponse(Set.of(SampleResource.fromXContent(parser))));
                    }
                }
            }, listener::onFailure));
        }
    }

    private void getResource(GetResourceRequest request, ActionListener<GetResponse> listener) {
        GetRequest getRequest = new GetRequest(RESOURCE_INDEX_NAME, request.getResourceId());

        nodeClient.get(getRequest, listener);
    }

    private void getAllResourcesAction(ActionListener<GetResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            getAllResources(ActionListener.wrap(searchResponse -> {
                SearchHit[] hits = searchResponse.getHits().getHits();
                if (hits.length == 0) {
                    listener.onFailure(new ResourceNotFoundException("No resources found in index: " + RESOURCE_INDEX_NAME));
                    return;
                }

                Set<SampleResource> resources = new HashSet<>();
                try {
                    for (SearchHit hit : hits) {
                        try (
                            XContentParser parser = XContentType.JSON.xContent()
                                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString())
                        ) {
                            resources.add(SampleResource.fromXContent(parser));
                        }
                    }
                    listener.onResponse(new GetResourceResponse(resources));
                } catch (Exception e) {
                    listener.onFailure(new ResourceSharingException("Failed to parse resources: " + e.getMessage(), e));
                }
            }, listener::onFailure));
        }
    }

    private void getAllResources(ActionListener<SearchResponse> listener) {
        SearchRequest searchRequest = new SearchRequest(RESOURCE_INDEX_NAME);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        searchSourceBuilder.size(1000);

        searchRequest.source(searchSourceBuilder);
        nodeClient.search(searchRequest, listener);
    }

}
