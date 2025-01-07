/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

public enum Creator {
    USER("user");

    private final String name;

    Creator(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
