/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.dashboards;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
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

    private static final Logger LOGGER = LogManager.getLogger(DashboardsResourceSharingExtension.class);

    // Access levels are expressed as document-level action strings, since that is what a saved-object request carries.
    private static final List<String> READ_ACTIONS = List.of(
        "indices:data/read/get",
        "indices:data/read/mget*",
        "indices:data/read/search*"
    );
    private static final List<String> READ_WRITE_ACTIONS = List.of(
        "indices:data/read/*",
        "indices:data/write/index*",
        "indices:data/write/update*",
        "indices:data/write/bulk*"
    );
    private static final List<String> FULL_ACCESS_ACTIONS = List.of(
        "indices:data/read/*",
        "indices:data/write/*",
        "cluster:admin/security/resource/share"
    );

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

    /**
     * Registers access levels for the built-in types.
     * <p>
     * Deliberately not done through a {@code resource-access-levels.yml}: that file is resolved per extension from a
     * fixed name on the classloader, so a copy shipped inside this plugin would be ambiguous with a plugin's own copy
     * wherever both are visible on one classpath. Registering directly keeps the built-in types self-contained.
     */
    public static void registerAccessLevels(ResourcePluginInfo resourcePluginInfo) {
        register(resourcePluginInfo, WORKSPACE_TYPE);
        for (String type : SHAREABLE_TYPES) {
            register(resourcePluginInfo, type);
        }
    }

    private static void register(ResourcePluginInfo resourcePluginInfo, String type) {
        // Level names are derived from the type, so "index-pattern" yields index_pattern_read_only etc.
        String prefix = type.replace('-', '_');
        String readOnly = prefix + "_read_only";

        Map<String, Object> levels = new LinkedHashMap<>();
        levels.put(readOnly, allowedActions(READ_ACTIONS));
        levels.put(prefix + "_read_write", allowedActions(READ_WRITE_ACTIONS));
        levels.put(prefix + "_full_access", allowedActions(FULL_ACCESS_ACTIONS));

        try {
            SecurityDynamicConfiguration<ActionGroupsV7> cfg = SecurityDynamicConfiguration.fromMap(levels, CType.ACTIONGROUPS);
            resourcePluginInfo.registerAccessLevels(type, cfg, readOnly);
        } catch (Exception e) {
            LOGGER.error("Failed to register access levels for built-in Dashboards type {}", type, e);
        }
    }

    private static Map<String, Object> allowedActions(List<String> actions) {
        Map<String, Object> level = new LinkedHashMap<>();
        level.put("allowed_actions", actions);
        return level;
    }
}
