/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import java.io.IOException;
import java.util.Map;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request object for revoking access to a sample resource
 */
public class RevokeResourceAccessRequest extends ActionRequest {

    String resourceId;
    Map<String, Object> entitiesToRevoke;

    public RevokeResourceAccessRequest(String resourceId, Map<String, Object> entitiesToRevoke) {
        this.resourceId = resourceId;
        this.entitiesToRevoke = entitiesToRevoke;
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        resourceId = in.readString();
        entitiesToRevoke = in.readMap();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeMap(entitiesToRevoke);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Map<String, Object> getEntitiesToRevoke() {
        return entitiesToRevoke;
    }
}
