/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.dashboards;

import java.util.HashSet;
import java.util.Set;

import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/**
 * Brings OpenSearch Dashboards saved objects under resource sharing without requiring a separate OpenSearch-side
 * plugin. Dashboards is a Node.js application, so nothing on the OpenSearch side can implement
 * {@link ResourceSharingExtension} for it; this built-in extension fills that gap.
 * <p>
 * Saved objects of every type live in one index and carry their type in a {@code type} field, so each shareable type
 * is registered as its own resource type over that shared index. {@code workspace} is registered too, which is what
 * lets the write-path container fan-out resolve a workspace's own sharing record.
 * <p>
 * Registration alone changes nothing: a type is only enforced once an operator adds it to
 * {@code plugins.security.resource_sharing.protected_types}, and this extension is only registered at all when
 * {@code plugins.security.resource_sharing.dashboards_onboarding.enabled} is set.
 */
public class DashboardsResourceSharingExtension implements ResourceSharingExtension {

    /** Matches the {@code workspace} type name the write-path container fan-out looks up. */
    public static final String WORKSPACE_TYPE = "workspace";

    private static final String TYPE_FIELD = "type";
    private static final String WORKSPACES_FIELD = "workspaces";

    /** Saved-object types brought under sharing. Deliberately excludes internal types such as {@code config}. */
    static final Set<String> SHAREABLE_TYPES = Set.of("dashboard", "visualization", "search", "index-pattern");

    private final String dashboardsIndex;

    public DashboardsResourceSharingExtension(String dashboardsIndex) {
        this.dashboardsIndex = dashboardsIndex;
    }

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        Set<ResourceProvider> providers = new HashSet<>();
        // A workspace is a container, not a member of one, so it declares no workspaces field.
        providers.add(provider(WORKSPACE_TYPE, null));
        for (String type : SHAREABLE_TYPES) {
            providers.add(provider(type, WORKSPACES_FIELD));
        }
        return providers;
    }

    private ResourceProvider provider(String type, String workspacesField) {
        return new ResourceProvider() {
            @Override
            public String resourceType() {
                return type;
            }

            @Override
            public String resourceIndexName() {
                return dashboardsIndex;
            }

            @Override
            public String typeField() {
                return TYPE_FIELD;
            }

            @Override
            public String workspacesField() {
                return workspacesField;
            }
        };
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient client) {
        // No-op: enforcement for these types happens inside the security plugin, so there is no in-process consumer
        // that needs the client handed to it.
    }
}
