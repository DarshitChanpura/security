/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;

public class GetResourceResponse extends ActionResponse implements ToXContentObject {
    private final SampleResource resource;

    /**
     * Default constructor
     *
     * @param resource The resource
     */
    public GetResourceResponse(SampleResource resource) {
        this.resource = resource;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeNamedWriteable(resource);
    }

    /**
     * Constructor with StreamInput
     *
     * @param in the stream input
     */
    public GetResourceResponse(final StreamInput in) throws IOException {
        resource = in.readNamedWriteable(SampleResource.class);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resource", resource);
        builder.endObject();
        return builder;
    }
}
