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

import org.opensearch.OpenSearchException;
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
 * Saved objects reference each other: a dashboard names the visualizations and index-patterns it renders. Sharing
 * one object does not reach its references, and each referenced type is registered independently here, so a
 * directly shared dashboard whose index-pattern was not also shared renders broken. Workspace-derived access is
 * unaffected, because membership grants every object in the workspace, references included. Resolving the
 * reference graph is therefore only needed for direct per-object sharing, which is separately blocked on the
 * saved-object index being strictly mapped.
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

    // Access levels are expressed as document-level action strings, since that is what a saved-object request carries.
    //
    // Reads are not action-gated: shouldEvaluate skips GetRequest and searches are never evaluated, so read
    // visibility is enforced by the DLS filter instead. A read level therefore denotes the absence of write access
    // rather than granting the read itself, and is kept broad so it stays correct if a read path is ever evaluated.
    private static final List<String> READ_ACTIONS = List.of("indices:data/read/*");
    // bulk* is inert today: BulkShardRequest is not a DocRequest, so bulk writes are not evaluated until they are
    // decomposed per item. It is listed so this level stays correct once that lands.
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
    private final WorkspaceMembershipCache membershipCache;

    public DashboardsResourceSharingExtension(String dashboardsIndex, WorkspaceMembershipCache membershipCache) {
        this.dashboardsIndex = dashboardsIndex;
        this.membershipCache = membershipCache;
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
     * Derived from the {@code workspace} sharing records rather than from an external source, so it satisfies the
     * trusted, I/O-free contract: the records are owned by this plugin and are read on a schedule, not on this call.
     */
    @Override
    public Set<String> resolveWorkspacesForUser(String username, Set<String> securityRoles, Set<String> backendRoles) {
        return membershipCache.resolve(username, securityRoles, backendRoles);
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
            // Fail loudly. A type registered with no access levels authorizes nothing, so swallowing this would
            // leave a cluster that looks healthy while every shared request is silently denied.
            throw new OpenSearchException("Failed to register access levels for built-in Dashboards type " + type, e);
        }
    }

    private static Map<String, Object> allowedActions(List<String> actions) {
        Map<String, Object> level = new LinkedHashMap<>();
        level.put("allowed_actions", actions);
        return level;
    }
}
