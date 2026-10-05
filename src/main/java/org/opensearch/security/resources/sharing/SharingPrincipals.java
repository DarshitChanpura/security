/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.sharing;

/**
 * The single encoding of the principal strings that sharing visibility is matched on.
 * <p>
 * Three separate places have to agree on this encoding: {@link ResourceSharing#getAllPrincipals()} writes it onto the
 * resource document, the DLS filter builds the caller's side of the comparison, and workspace membership resolution
 * reverse-indexes it. A mismatch between any two of them does not fail loudly, it silently matches nothing, so the
 * prefixes live here rather than as literals at each site.
 */
public final class SharingPrincipals {

    /** Matches resources shared via general access, so reachable by every authenticated user. */
    public static final String PUBLIC = "public";

    private static final String USER_PREFIX = "user:";
    private static final String ROLE_PREFIX = "role:";
    private static final String BACKEND_ROLE_PREFIX = "backend:";

    private SharingPrincipals() {}

    public static String user(String username) {
        return USER_PREFIX + username;
    }

    public static String role(String securityRole) {
        return ROLE_PREFIX + securityRole;
    }

    public static String backendRole(String backendRole) {
        return BACKEND_ROLE_PREFIX + backendRole;
    }
}
