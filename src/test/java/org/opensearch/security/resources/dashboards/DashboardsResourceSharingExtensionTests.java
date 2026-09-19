/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.dashboards;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.spi.resources.ResourceProvider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the built-in Dashboards saved-object resource types.
 */
public class DashboardsResourceSharingExtensionTests {

    private static final String INDEX = ".kibana";

    private ResourcePluginInfo registered() {
        ResourcePluginInfo info = new ResourcePluginInfo();
        info.setResourceSharingExtensions(Set.of(new DashboardsResourceSharingExtension(INDEX)));
        return info;
    }

    @Test
    public void declaresWorkspaceAndShareableTypesOnTheDashboardsIndex() {
        DashboardsResourceSharingExtension ext = new DashboardsResourceSharingExtension(INDEX);
        Set<String> types = ext.getResourceProviders().stream().map(ResourceProvider::resourceType).collect(Collectors.toSet());

        // The workspace type must be present: the write-path container fan-out resolves a workspace's own record by it.
        assertTrue(types.contains(DashboardsResourceSharingExtension.WORKSPACE_TYPE));
        assertTrue(types.containsAll(DashboardsResourceSharingExtension.SHAREABLE_TYPES));

        for (ResourceProvider p : ext.getResourceProviders()) {
            assertEquals(INDEX, p.resourceIndexName());
            assertEquals("type", p.typeField());
        }
    }

    @Test
    public void workspaceTypeDeclaresNoWorkspacesFieldButMembersDo() {
        DashboardsResourceSharingExtension ext = new DashboardsResourceSharingExtension(INDEX);
        for (ResourceProvider p : ext.getResourceProviders()) {
            if (DashboardsResourceSharingExtension.WORKSPACE_TYPE.equals(p.resourceType())) {
                // A workspace is a container, not a member of one.
                assertNull(p.workspacesField());
            } else {
                assertEquals("workspaces", p.workspacesField());
            }
        }
    }

    @Test
    public void providersResolveThroughResourcePluginInfoOnceProtected() {
        ResourcePluginInfo info = registered();
        info.updateProtectedTypes(List.of(DashboardsResourceSharingExtension.WORKSPACE_TYPE, "dashboard"));

        assertEquals(INDEX, info.indexByType(DashboardsResourceSharingExtension.WORKSPACE_TYPE));
        assertEquals(INDEX, info.indexByType("dashboard"));
        // DLS narrows on this field; all member types on the index agree on it, so resolution is unambiguous.
        assertEquals("workspaces", info.workspacesFieldForIndex(INDEX));
    }

    @Test
    public void nonProtectedTypesAreNotEnforced() {
        ResourcePluginInfo info = registered();
        // Only the workspace container is opted in; a saved-object type left out must not resolve.
        info.updateProtectedTypes(List.of(DashboardsResourceSharingExtension.WORKSPACE_TYPE));

        assertEquals(INDEX, info.indexByType(DashboardsResourceSharingExtension.WORKSPACE_TYPE));
        // getResourceProvider is the nullable lookup; indexByType assumes the type is registered.
        assertNull(info.getResourceProvider("dashboard"));
    }

    @Test
    public void registrationIsInertWhenNoTypesAreProtected() {
        ResourcePluginInfo info = registered();
        // An empty protected_types list must leave the index set empty, so the index listener is not attached to the
        // Dashboards index and no sharing index is created for it.
        info.updateProtectedTypes(List.of());

        assertTrue(info.getResourceIndices().isEmpty());
    }

    @Test
    public void registersAccessLevelsProgrammatically() {
        ResourcePluginInfo info = registered();
        DashboardsResourceSharingExtension.registerAccessLevels(info);
        info.updateProtectedTypes(List.of(DashboardsResourceSharingExtension.WORKSPACE_TYPE, "dashboard", "index-pattern"));

        // Three levels per type, and the read-only level is the registered default.
        Set<String> workspaceLevels = info.getResourceTypes()
            .stream()
            .filter(t -> DashboardsResourceSharingExtension.WORKSPACE_TYPE.equals(t.resourceType()))
            .flatMap(t -> t.accessLevels().stream())
            .collect(Collectors.toSet());
        assertEquals(Set.of("workspace_read_only", "workspace_read_write", "workspace_full_access"), workspaceLevels);
        assertEquals("workspace_read_only", info.getDefaultAccessLevel(DashboardsResourceSharingExtension.WORKSPACE_TYPE));

        // A hyphenated type yields underscored level names.
        assertEquals("index_pattern_read_only", info.getDefaultAccessLevel("index-pattern"));

        // Levels resolve to concrete actions, so the write-path check has something to match against.
        assertTrue(info.flattenedForType("dashboard").resolve(Set.of("dashboard_read_only")).contains("indices:data/read/get"));
    }

    @Test
    public void mixedWorkspacesFieldDeclarationsDoNotConflict() {
        // The workspace type declares null and the member types declare "workspaces"; registration must accept that
        // (only conflicting non-null declarations on one index are rejected).
        ResourcePluginInfo info = registered();
        info.updateProtectedTypes(
            List.of(DashboardsResourceSharingExtension.WORKSPACE_TYPE, "dashboard", "visualization", "search", "index-pattern")
        );
        assertEquals("workspaces", info.workspacesFieldForIndex(INDEX));
    }
}
