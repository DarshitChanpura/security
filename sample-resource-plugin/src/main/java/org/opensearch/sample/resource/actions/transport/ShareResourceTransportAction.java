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

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceAction;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceRequest;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceResponse;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.client.resources.ResourceSharingClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class ShareResourceTransportAction extends HandledTransportAction<ShareResourceRequest, ShareResourceResponse> {
    private static final Logger log = LogManager.getLogger(ShareResourceTransportAction.class);

    private final NodeClient nodeClient;

    @Inject
    public ShareResourceTransportAction(TransportService transportService, ActionFilters actionFilters, NodeClient nodeClient) {
        super(ShareResourceAction.NAME, transportService, actionFilters, ShareResourceRequest::new);
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }

        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient);
        resourceSharingClient.shareResource(
            request.getResourceId(),
            RESOURCE_INDEX_NAME,
            request.getShareWith(),
            ActionListener.wrap(sharing -> {
                ShareResourceResponse response = new ShareResourceResponse(sharing.getShareWith());
                listener.onResponse(response);
            }, listener::onFailure)
        );
    }

}
