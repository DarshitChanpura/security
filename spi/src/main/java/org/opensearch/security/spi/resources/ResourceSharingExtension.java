/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

/**
 * This interface should be implemented by all the plugins that define one or more resources and need access control over those resources.
 *
 * @opensearch.experimental
 */
public interface ResourceSharingExtension {

    /**
     * Type of the resource
     * @return a string containing the type of the resource. A qualified class name can be supplied here.
     */
    String getResourceType();

    /**
     * The index where resource is stored
     * @return the name of the parent index where resource is stored
     */
    String getResourceIndex();

    /**
     * The parser for the resource, which will be used by security plugin to parse the resource
     * @return the parser for the resource
     */
    ResourceParser<? extends Resource> getResourceParser();
}
