/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourceScope;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceAction;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceRequest;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceResponse;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.client.resources.ResourceSharingClient;
import org.opensearch.security.spi.resources.exceptions.ResourceSharingException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for deleting a resource
 */
public class DeleteResourceTransportAction extends HandledTransportAction<DeleteResourceRequest, DeleteResourceResponse> {
    private static final Logger log = LogManager.getLogger(DeleteResourceTransportAction.class);

    private final TransportService transportService;
    private final NodeClient nodeClient;
    private final Settings settings;

    @Inject
    public DeleteResourceTransportAction(
        Settings settings,
        TransportService transportService,
        ActionFilters actionFilters,
        NodeClient nodeClient
    ) {
        super(DeleteResourceAction.NAME, transportService, actionFilters, DeleteResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
        this.settings = settings;
    }

    @Override
    protected void doExecute(Task task, DeleteResourceRequest request, ActionListener<DeleteResourceResponse> listener) {

        String resourceId = request.getResourceId();
        if (resourceId == null || resourceId.isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }

        // Check permission to resource
        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient, settings);
        resourceSharingClient.verifyResourceAccess(
            resourceId,
            RESOURCE_INDEX_NAME,
            SampleResourceScope.PUBLIC.value(),
            ActionListener.wrap(isAuthorized -> {
                if (!isAuthorized) {
                    listener.onFailure(new ResourceSharingException("Current user is not authorized to delete resource: " + resourceId));
                    return;
                }

                // Authorization successful, proceed with deletion
                ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
                try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
                    deleteResource(resourceId, ActionListener.wrap(deleteResponse -> {
                        if (deleteResponse.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                            listener.onFailure(new ResourceNotFoundException("Resource " + resourceId + " not found."));
                        } else {
                            listener.onResponse(new DeleteResourceResponse("Resource " + resourceId + " deleted successfully."));
                        }
                    }, exception -> {
                        log.error("Failed to delete resource: " + resourceId, exception);
                        listener.onFailure(exception);
                    }));
                }
            }, exception -> {
                log.error("Failed to verify resource access: " + resourceId, exception);
                listener.onFailure(exception);
            })
        );
    }

    private void deleteResource(String resourceId, ActionListener<DeleteResponse> listener) {
        DeleteRequest deleteRequest = new DeleteRequest(RESOURCE_INDEX_NAME, resourceId).setRefreshPolicy(
            WriteRequest.RefreshPolicy.IMMEDIATE
        );

        nodeClient.delete(deleteRequest, listener);
    }

}
