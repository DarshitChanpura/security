/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.dashboards;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import org.opensearch.security.resources.SharingRecord;
import org.opensearch.security.resources.sharing.CreatedBy;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for deriving workspace membership from workspace sharing records.
 */
public class WorkspaceMembershipCacheTests {

    private static SharingRecord workspace(String id, String owner, ShareWith shareWith) {
        ResourceSharing sharing = ResourceSharing.builder()
            .resourceId(id)
            .resourceType(DashboardsResourceSharingExtension.WORKSPACE_TYPE)
            .createdBy(new CreatedBy(owner))
            .shareWith(shareWith)
            .build();
        return new SharingRecord(sharing, false);
    }

    private static ShareWith sharedWith(String accessLevel, Recipient recipient, String... names) {
        return new ShareWith(Map.of(accessLevel, new Recipients(Map.of(recipient, Set.of(names)))));
    }

    private WorkspaceMembershipCache cacheOf(List<SharingRecord> records) {
        WorkspaceMembershipCache cache = new WorkspaceMembershipCache(".kibana");
        cache.rebuild(records);
        return cache;
    }

    @Test
    public void resolvesNothingBeforeFirstRefresh() {
        // Fail closed: with no snapshot yet, workspace-derived visibility is simply off.
        WorkspaceMembershipCache cache = new WorkspaceMembershipCache(".kibana");
        assertTrue(cache.resolve("alice", Set.of("role_a"), Set.of("backend_a")).isEmpty());
    }

    @Test
    public void ownerIsAMember() {
        WorkspaceMembershipCache cache = cacheOf(List.of(workspace("ws-1", "alice", null)));

        assertEquals(Set.of("ws-1"), cache.resolve("alice", Set.of(), Set.of()));
        assertTrue(cache.resolve("bob", Set.of(), Set.of()).isEmpty());
    }

    @Test
    public void resolvesByUsernameRoleAndBackendRole() {
        WorkspaceMembershipCache cache = cacheOf(
            List.of(
                workspace("ws-user", "owner", sharedWith("workspace_read_only", Recipient.USERS, "alice")),
                workspace("ws-role", "owner", sharedWith("workspace_read_only", Recipient.ROLES, "analyst")),
                workspace("ws-backend", "owner", sharedWith("workspace_read_only", Recipient.BACKEND_ROLES, "ldap_team"))
            )
        );

        assertEquals(Set.of("ws-user"), cache.resolve("alice", Set.of(), Set.of()));
        assertEquals(Set.of("ws-role"), cache.resolve("bob", Set.of("analyst"), Set.of()));
        assertEquals(Set.of("ws-backend"), cache.resolve("bob", Set.of(), Set.of("ldap_team")));
        // All three channels union together.
        assertEquals(
            Set.of("ws-user", "ws-role", "ws-backend"),
            cache.resolve("alice", Set.of("analyst"), Set.of("ldap_team"))
        );
    }

    @Test
    public void resolvesMultipleWorkspacesForOneUser() {
        WorkspaceMembershipCache cache = cacheOf(
            List.of(
                workspace("ws-1", "owner", sharedWith("workspace_read_only", Recipient.USERS, "alice")),
                workspace("ws-2", "owner", sharedWith("workspace_read_write", Recipient.USERS, "alice")),
                workspace("ws-3", "owner", sharedWith("workspace_read_only", Recipient.USERS, "bob"))
            )
        );

        // Membership is 1:N, so a user reaches every workspace shared with them at any level.
        assertEquals(Set.of("ws-1", "ws-2"), cache.resolve("alice", Set.of(), Set.of()));
    }

    @Test
    public void unsharedWorkspaceIsNotVisibleToOthers() {
        WorkspaceMembershipCache cache = cacheOf(
            List.of(workspace("ws-private", "owner", sharedWith("workspace_read_only", Recipient.USERS, "alice")))
        );

        assertTrue(cache.resolve("intruder", Set.of("unrelated_role"), Set.of("unrelated_backend")).isEmpty());
    }

    @Test
    public void rebuildReplacesPreviousSnapshot() {
        WorkspaceMembershipCache cache = cacheOf(
            List.of(workspace("ws-1", "owner", sharedWith("workspace_read_only", Recipient.USERS, "alice")))
        );
        assertEquals(Set.of("ws-1"), cache.resolve("alice", Set.of(), Set.of()));

        // A revoke shows up as the record no longer naming alice; the snapshot is replaced wholesale.
        cache.rebuild(List.of(workspace("ws-1", "owner", sharedWith("workspace_read_only", Recipient.USERS, "bob"))));
        assertTrue(cache.resolve("alice", Set.of(), Set.of()).isEmpty());
        assertEquals(Set.of("ws-1"), cache.resolve("bob", Set.of(), Set.of()));
    }

    @Test
    public void handlesRecordsWithoutShareWith() {
        // A workspace nobody has been granted access to yet still resolves for its creator only.
        WorkspaceMembershipCache cache = cacheOf(List.of(workspace("ws-1", "alice", null), workspace("ws-2", "bob", null)));

        assertEquals(Set.of("ws-1"), cache.resolve("alice", Set.of(), Set.of()));
        assertEquals(Set.of("ws-2"), cache.resolve("bob", Set.of(), Set.of()));
    }

    @Test
    public void nullIdentityFieldsAreTolerated() {
        WorkspaceMembershipCache cache = cacheOf(
            List.of(workspace("ws-1", "owner", sharedWith("workspace_read_only", Recipient.USERS, "alice")))
        );
        assertTrue(cache.resolve(null, null, null).isEmpty());
    }
}
