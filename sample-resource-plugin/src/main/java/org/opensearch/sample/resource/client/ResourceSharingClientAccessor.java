package org.opensearch.sample.resource.client;

import org.opensearch.security.client.resources.ResourceSharingNodeClient;
import org.opensearch.transport.client.node.NodeClient;

public class ResourceSharingClientAccessor {
    private static ResourceSharingNodeClient INSTANCE;

    private ResourceSharingClientAccessor() {}

    /**
     * get machine learning client.
     *
     * @param nodeClient node client
     * @return machine learning client
     */
    public static ResourceSharingNodeClient getResourceSharingClient(NodeClient nodeClient) {
        if (INSTANCE == null) {
            INSTANCE = new ResourceSharingNodeClient(nodeClient);
        }
        return INSTANCE;
    }
}
