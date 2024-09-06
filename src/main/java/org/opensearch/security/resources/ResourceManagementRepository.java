package org.opensearch.security.resources;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

public class ResourceManagementRepository {

    private static final Logger LOGGER = LogManager.getLogger(ConfigurationRepository.class);

    private final Client client;

    private final ThreadPool threadPool;

    private final ResourceSharingIndexHandler resourceSharingIndexHandler;

    protected ResourceManagementRepository(
        final ThreadPool threadPool,
        final Client client,
        final ResourceSharingIndexHandler resourceSharingIndexHandler
    ) {
        this.client = client;
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
    }

    public static ResourceManagementRepository create(Settings settings, final ThreadPool threadPool, Client client) {
        final var resourceSharingIndex = ConfigConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
        return new ResourceManagementRepository(
            threadPool,
            client,
            new ResourceSharingIndexHandler(resourceSharingIndex, settings, client, threadPool)
        );
    }

    public void createResourceSharingIndexIfAbsent() {
        // TODO check if this should be wrapped in an atomic completable future

        this.resourceSharingIndexHandler.createResourceSharingIndexIfAbsent(() -> null);
    }

}
