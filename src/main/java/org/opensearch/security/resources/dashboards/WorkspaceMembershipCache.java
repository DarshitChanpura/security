/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.dashboards;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.resources.SharingRecord;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.SharingPrincipals;
import org.opensearch.threadpool.ThreadPool;

/**
 * Resolves which workspaces a user can reach, from the sharing records of the {@code workspace} resource type.
 * <p>
 * Workspace membership is already expressed as resource sharing: a {@code workspace} record's {@code share_with} names
 * the users, roles and backend roles that hold access to it. So membership needs no external resolver: it is derived
 * from records this plugin already owns, which also makes it inherently server-set rather than user-assertable.
 * <p>
 * Resolution happens on the privilege hot path and must not perform I/O, so records are read on a schedule into a
 * principal-to-workspaces snapshot and {@link #resolve} only reads that snapshot.
 * <p>
 * Consequences worth knowing:
 * <ul>
 *   <li>Membership changes take effect no later than one refresh interval, so a revoked collaborator may retain
 *       workspace-derived read visibility until the next refresh. Narrow the interval if that window matters.</li>
 *   <li>Before the first successful refresh, and if every refresh fails, resolution returns nothing, so workspace-derived
 *       visibility is simply off rather than over-granted.</li>
 * </ul>
 */
public class WorkspaceMembershipCache {

    private static final Logger LOGGER = LogManager.getLogger(WorkspaceMembershipCache.class);

    private final String dashboardsIndex;

    /** Immutable snapshot, replaced wholesale by a refresh so readers never observe a partially built map. */
    private volatile Map<String, Set<String>> principalToWorkspaces = Map.of();

    public WorkspaceMembershipCache(String dashboardsIndex) {
        this.dashboardsIndex = dashboardsIndex;
    }

    /**
     * Workspaces reachable by the given identity. I/O-free: reads only the current snapshot.
     */
    public Set<String> resolve(String username, Set<String> securityRoles, Set<String> backendRoles) {
        Map<String, Set<String>> snapshot = principalToWorkspaces;
        if (snapshot.isEmpty()) {
            return Set.of();
        }

        Set<String> workspaces = new HashSet<>();
        addMatches(workspaces, snapshot, SharingPrincipals.PUBLIC);
        if (username != null) {
            addMatches(workspaces, snapshot, SharingPrincipals.user(username));
        }
        if (securityRoles != null) {
            for (String role : securityRoles) {
                addMatches(workspaces, snapshot, SharingPrincipals.role(role));
            }
        }
        if (backendRoles != null) {
            for (String backendRole : backendRoles) {
                addMatches(workspaces, snapshot, SharingPrincipals.backendRole(backendRole));
            }
        }
        return workspaces;
    }

    private static void addMatches(Set<String> target, Map<String, Set<String>> snapshot, String principal) {
        Set<String> workspaces = snapshot.get(principal);
        if (workspaces != null) {
            target.addAll(workspaces);
        }
    }

    /**
     * Schedules the first refresh and then repeats it on a fixed delay. Safe to call once the sharing index handler
     * exists.
     * <p>
     * The first refresh is scheduled rather than run inline because this is called while the node is still being
     * constructed, where the sharing index does not exist yet and the client cannot serve a search. Running it on the
     * calling thread would both fail every time and, if the search threw synchronously, propagate out of component
     * construction and fail node start.
     */
    public void start(ResourceSharingIndexHandler sharingIndexHandler, ThreadPool threadPool, TimeValue refreshInterval) {
        threadPool.schedule(() -> refresh(sharingIndexHandler), TimeValue.ZERO, ThreadPool.Names.GENERIC);
        threadPool.scheduleWithFixedDelay(() -> refresh(sharingIndexHandler), refreshInterval, ThreadPool.Names.GENERIC);
        LOGGER.info("Workspace membership resolution enabled for index {}, refreshing every {}", dashboardsIndex, refreshInterval);
    }

    void refresh(ResourceSharingIndexHandler sharingIndexHandler) {
        try {
            fetch(sharingIndexHandler);
        } catch (Exception e) {
            // A synchronous failure must not escape: on the scheduled path it would kill the recurring task, and
            // the first run happens while the node is still starting.
            LOGGER.warn("Failed to start a workspace membership refresh, keeping the previous snapshot: {}", e.toString());
        }
    }

    private void fetch(ResourceSharingIndexHandler sharingIndexHandler) {
        sharingIndexHandler.fetchAllResourceSharingRecords(
            dashboardsIndex,
            DashboardsResourceSharingExtension.WORKSPACE_TYPE,
            ActionListener.wrap(this::rebuild, e -> {
                // Keep serving the previous snapshot: dropping it would revoke visibility across the cluster on a
                // single failed read.
                LOGGER.warn("Failed to refresh workspace membership, keeping the previous snapshot: {}", e.toString());
            })
        );
    }

    /** Builds the principal-to-workspaces reverse index from the given workspace sharing records. */
    void rebuild(Collection<SharingRecord> workspaceRecords) {
        Map<String, Set<String>> next = new HashMap<>();
        for (SharingRecord record : workspaceRecords) {
            ResourceSharing sharing = record.resourceSharing();
            if (sharing == null || sharing.getResourceId() == null) {
                continue;
            }
            String workspaceId = sharing.getResourceId();
            // getAllPrincipals already yields the creator, every share recipient, and "public" for general access.
            for (String principal : sharing.getAllPrincipals()) {
                next.computeIfAbsent(principal, k -> new HashSet<>()).add(workspaceId);
            }
        }

        Map<String, Set<String>> snapshot = new HashMap<>();
        next.forEach((principal, workspaces) -> snapshot.put(principal, Set.copyOf(workspaces)));
        principalToWorkspaces = Map.copyOf(snapshot);

        LOGGER.debug("Workspace membership refreshed: {} principals across {} records", snapshot.size(), workspaceRecords.size());
    }
}
