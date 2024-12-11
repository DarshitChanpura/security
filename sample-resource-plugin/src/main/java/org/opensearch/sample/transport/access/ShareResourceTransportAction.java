/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport.access;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.access.share.ShareResourceAction;
import org.opensearch.sample.actions.access.share.ShareResourceRequest;
import org.opensearch.sample.actions.access.share.ShareResourceResponse;
import org.opensearch.sample.utils.SampleResourcePluginException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class ShareResourceTransportAction extends HandledTransportAction<ShareResourceRequest, ShareResourceResponse> {
    private static final Logger log = LogManager.getLogger(ShareResourceTransportAction.class);

    @Inject
    public ShareResourceTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(ShareResourceAction.NAME, transportService, actionFilters, ShareResourceRequest::new);
    }

    @Override
    protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
        ResourceSharing sharing = null;
        try {
            sharing = shareResource(request);
            if (sharing == null) {
                log.error("Failed to share resource {}", request.getResourceId());
                SampleResourcePluginException se = new SampleResourcePluginException("Failed to share resource " + request.getResourceId());
                listener.onFailure(se);
                return;
            }
            log.info("Shared resource : {} with {}", request.getResourceId(), sharing.toString());
            listener.onResponse(new ShareResourceResponse("Resource " + request.getResourceId() + " shared successfully."));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private ResourceSharing shareResource(ShareResourceRequest request) throws Exception {
        ResourceService rs = SampleResourcePlugin.GuiceHolder.getResourceService();
        return rs.getResourceAccessControlPlugin().shareWith(request.getResourceId(), RESOURCE_INDEX_NAME, request.getShareWith());
    }
}