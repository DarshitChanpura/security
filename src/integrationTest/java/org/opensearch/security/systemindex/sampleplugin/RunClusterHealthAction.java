/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.systemindex.sampleplugin;

import org.opensearch.action.ActionType;

public class RunClusterHealthAction extends ActionType<RunClusterHealthResponse> {
    public static final RunClusterHealthAction INSTANCE = new RunClusterHealthAction();
    public static final String NAME = "cluster:mock/monitor/health";

    private RunClusterHealthAction() {
        super(NAME, RunClusterHealthResponse::new);
    }
}
