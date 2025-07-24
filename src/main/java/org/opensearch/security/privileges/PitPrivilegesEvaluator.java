/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.privileges;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.indices.segments.PitSegmentsRequest;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resolver.IndexResolverReplacer;

/**
 * This class evaluates privileges for point in time (Delete and List all) operations.
 * For aliases - users must have either alias permission or backing index permissions
 * For data streams - users must have access to backing indices permission + data streams permission.
 */
public class PitPrivilegesEvaluator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String PIT_FIELD = "pit"; // it does rely on the field name as "pit"
    private static final String PIT_ID_FIELD = "id";

    public PrivilegesEvaluatorResponse evaluate(
        final ActionRequest request,
        final PrivilegesEvaluationContext context,
        final ActionPrivileges actionPrivileges,
        final String action,
        final PrivilegesEvaluatorResponse presponse,
        final IndexResolverReplacer irr
    ) {

        boolean isPitSearch = request instanceof SearchRequest && ((SearchRequest) request).source().toString().contains(PIT_FIELD);
        boolean isDeletePit = request instanceof DeletePitRequest;
        boolean isPitSegments = request instanceof PitSegmentsRequest;

        // return if its
        if (!isPitSearch && !isDeletePit && !isPitSegments) {
            return presponse;
        }

        List<String> pitIds = new ArrayList<>();

        if (request instanceof DeletePitRequest) {
            DeletePitRequest deletePitRequest = (DeletePitRequest) request;
            pitIds = deletePitRequest.getPitIds();
        } else if (request instanceof PitSegmentsRequest) {
            PitSegmentsRequest pitSegmentsRequest = (PitSegmentsRequest) request;
            pitIds = pitSegmentsRequest.getPitIds();
        } else if (request instanceof SearchRequest) {
            pitIds = extractPitIdsFromSearchRequest(((SearchRequest) request).source());
        }
        // if request is for all PIT IDs, skip custom pit ids evaluation
        if (pitIds.size() == 1 && "_all".equals(pitIds.get(0))) {
            return presponse;
        } else {
            return handlePitsAccess(pitIds, context, actionPrivileges, action, presponse, irr);
        }
    }

    /**
     * Handle access for delete operation / pit segments operation where PIT IDs are explicitly passed
     */
    private PrivilegesEvaluatorResponse handlePitsAccess(
        List<String> pitIds,
        PrivilegesEvaluationContext context,
        ActionPrivileges actionPrivileges,
        final String action,
        PrivilegesEvaluatorResponse presponse,
        final IndexResolverReplacer irr
    ) {
        Map<String, String[]> pitToIndicesMap = OpenSearchSecurityPlugin.GuiceHolder.getPitService().getIndicesForPits(pitIds);
        Set<String> pitIndices = new HashSet<>();
        // add indices across all PITs to a set and evaluate if user has access to all indices
        for (String[] indices : pitToIndicesMap.values()) {
            pitIndices.addAll(Arrays.asList(indices));
        }
        String[] indicesArr = new String[pitIndices.size()];
        CreatePitRequest req = new CreatePitRequest(new TimeValue(1, TimeUnit.DAYS), true, pitIndices.toArray(indicesArr));
        final IndexResolverReplacer.Resolved pitResolved = irr.resolveRequest(req);
        PrivilegesEvaluatorResponse subResponse = actionPrivileges.hasIndexPrivilege(context, ImmutableSet.of(action), pitResolved);
        // Only if user has access to all PIT's indices, allow operation, otherwise continue evaluation in PrivilegesEvaluator.
        if (subResponse.isAllowed()) {
            presponse.allowed = true;
            presponse.markComplete();
        }

        return presponse;
    }

    public static List<String> extractPitIdsFromSearchRequest(SearchSourceBuilder source) {
        try {
            String json = source.toString();
            JsonNode root = MAPPER.readTree(json);
            JsonNode pitNode = root.path(PIT_FIELD);

            if (pitNode.isMissingNode() || pitNode.isNull()) {
                return Collections.emptyList();
            }

            List<String> ids = new ArrayList<>();

            // if pit is an array of objects
            if (pitNode.isArray()) {
                for (JsonNode element : pitNode) {
                    JsonNode idNode = element.get(PIT_ID_FIELD);
                    if (idNode != null && idNode.isTextual()) {
                        ids.add(idNode.asText());
                    }
                }
            }
            // if pit is a single object
            else if (pitNode.isObject()) {
                JsonNode idNode = pitNode.get(PIT_ID_FIELD);
                if (idNode != null && idNode.isTextual()) {
                    ids.add(idNode.asText());
                }
            }

            return ids;
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse SearchSourceBuilder JSON", e);
        }
    }
}
