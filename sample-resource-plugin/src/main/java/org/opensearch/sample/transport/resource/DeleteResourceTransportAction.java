/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport.resource;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.actions.resource.delete.DeleteResourceAction;
import org.opensearch.sample.actions.resource.delete.DeleteResourceRequest;
import org.opensearch.sample.actions.resource.delete.DeleteResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class DeleteResourceTransportAction extends HandledTransportAction<DeleteResourceRequest, DeleteResourceResponse> {
    private static final Logger log = LogManager.getLogger(DeleteResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;

    @Inject
    public DeleteResourceTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(DeleteResourceAction.NAME, transportService, actionFilters, DeleteResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, DeleteResourceRequest request, ActionListener<DeleteResourceResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }

        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            deleteResource(request, ActionListener.wrap(deleteResponse -> {
                if (deleteResponse.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                    listener.onFailure(new ResourceNotFoundException("Resource " + request.getResourceId() + " not found"));
                } else {
                    listener.onResponse(new DeleteResourceResponse("Resource " + request.getResourceId() + " deleted successfully"));
                }
            }, exception -> {
                log.error("Failed to delete resource: " + request.getResourceId(), exception);
                listener.onFailure(exception);
            }));
        }
    }

    private void deleteResource(DeleteResourceRequest request, ActionListener<DeleteResponse> listener) {
        DeleteRequest deleteRequest = new DeleteRequest(RESOURCE_INDEX_NAME, request.getResourceId()).setRefreshPolicy(
            WriteRequest.RefreshPolicy.IMMEDIATE
        );

        nodeClient.delete(deleteRequest, listener);
    }

}