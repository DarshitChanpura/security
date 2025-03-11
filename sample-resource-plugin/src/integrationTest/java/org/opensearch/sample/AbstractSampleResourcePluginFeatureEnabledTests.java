/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample;

import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.common.resources.ResourcePluginInfo;
import org.opensearch.security.common.resources.ResourceProvider;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.common.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This abstract class defines common tests between different feature flag scenarios
 */
public abstract class AbstractSampleResourcePluginFeatureEnabledTests extends AbstractSampleResourcePluginTests {

    protected abstract LocalCluster getLocalCluster();

    private LocalCluster cluster;

    @Before
    public void setup() {
        cluster = getLocalCluster();
    }

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX);
            ResourcePluginInfo.getInstance().getResourceIndicesMutable().remove(RESOURCE_INDEX_NAME);
            ResourcePluginInfo.getInstance().getResourceProvidersMutable().remove(RESOURCE_INDEX_NAME);
        }
    }

    @Test
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse pluginsResponse = client.get("_cat/plugins");
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.security.OpenSearchSecurityPlugin"));
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.sample.SampleResourcePlugin"));
        }
    }

    @Test
    public void testCreateUpdateDeleteSampleResourceWithSecurityAPIs() throws Exception {
        String resourceId;
        String resourceSharingDocId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = "{\"name\":\"sample\"}";
            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
        }

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = String.format(
                "{"
                    + "  \"source_idx\": \""
                    + RESOURCE_INDEX_NAME
                    + "\","
                    + "  \"resource_id\": \"%s\","
                    + "  \"created_by\": {"
                    + "    \"user\": \"admin\""
                    + "  }"
                    + "}",
                resourceId
            );
            TestRestClient.HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            resourceSharingDocId = response.bodyAsJsonNode().get("_id").asText();
            // Also update the in-memory map and get
            ResourcePluginInfo.getInstance().getResourceIndicesMutable().add(RESOURCE_INDEX_NAME);
            ResourceProvider provider = new ResourceProvider(
                SampleResource.class.getCanonicalName(),
                RESOURCE_INDEX_NAME,
                new SampleResourceParser()
            );
            ResourcePluginInfo.getInstance().getResourceProvidersMutable().put(RESOURCE_INDEX_NAME, provider);

            Thread.sleep(1000);
            response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
        }

        // Update sample resource (shared_with_user cannot update admin's resource)
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            String sampleResourceUpdated = "{\"name\":\"sampleUpdated\"}";
            TestRestClient.HttpResponse updateResponse = client.postJson(
                SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // Update sample resource (admin should be able to update resource)
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResourceUpdated = "{\"name\":\"sampleUpdated\"}";
            TestRestClient.HttpResponse updateResponse = client.postJson(
                SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
        }

        // resource should be visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {

            TestRestClient.HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // resource should no longer be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            TestRestClient.HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(0));
        }

        // shared_with_user should not be able to share admin's resource with itself
        // Only admins and owners can share/revoke access at the moment
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            TestRestClient.HttpResponse response = client.postJson(
                SECURITY_RESOURCE_SHARE_ENDPOINT,
                shareWithPayloadSecurityApi(resourceId)
            );
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("message").asText(),
                containsString("User " + SHARED_WITH_USER.getName() + " is not authorized")
            );
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);

            TestRestClient.HttpResponse response = client.postJson(
                SECURITY_RESOURCE_SHARE_ENDPOINT,
                shareWithPayloadSecurityApi(resourceId)
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(
                response.bodyAsJsonNode()
                    .get("sharing_info")
                    .get("share_with")
                    .get(SampleResourceScope.PUBLIC.value())
                    .get("users")
                    .get(0)
                    .asText(),
                containsString(SHARED_WITH_USER.getName())
            );
        }

        // resource should now be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // resource is still visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // verify access
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.postJson(SECURITY_RESOURCE_VERIFY_ENDPOINT, verifyAccessPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("has_permission").asBoolean(), equalTo(true));
        }

        // shared_with user should not be able to revoke access to admin's resource
        // Only admins and owners can share/revoke access at the moment
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.postJson(
                SECURITY_RESOURCE_REVOKE_ENDPOINT,
                revokeAccessPayloadSecurityApi(resourceId)
            );
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("message").asText(),
                containsString("User " + SHARED_WITH_USER.getName() + " is not authorized")
            );
        }

        // get sample resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // resource should be visible to shared_with_user since the resource is shared with this user and this user has * permission
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);
            TestRestClient.HttpResponse response = client.postJson(
                SECURITY_RESOURCE_REVOKE_ENDPOINT,
                revokeAccessPayloadSecurityApi(resourceId)
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("share_with"), nullValue());
        }

        // verify access - share_with_user should no longer have access to admin's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            TestRestClient.HttpResponse response = client.postJson(SECURITY_RESOURCE_VERIFY_ENDPOINT, verifyAccessPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("has_permission").asBoolean(), equalTo(false));
        }

        // get sample resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // delete sample resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // delete sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // corresponding entry should be removed from resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to delete the resource sharing entry manually
            TestRestClient.HttpResponse response = client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc/" + resourceSharingDocId);
            response.assertStatusCode(HttpStatus.SC_OK);

            Thread.sleep(2000);
            response = client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(0));
        }

        // get sample resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }

        // get sample resource with admin
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }
    }

    @Test
    public void testCreateUpdateDeleteSampleResource() throws Exception {
        String resourceId;
        String resourceSharingDocId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = "{\"name\":\"sample\"}";
            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
        }

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = String.format(
                "{"
                    + "  \"source_idx\": \".sample_resource_sharing_plugin\","
                    + "  \"resource_id\": \"%s\","
                    + "  \"created_by\": {"
                    + "    \"user\": \"admin\""
                    + "  }"
                    + "}",
                resourceId
            );
            TestRestClient.HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            resourceSharingDocId = response.bodyAsJsonNode().get("_id").asText();
            // Also update the in-memory map and get
            ResourcePluginInfo.getInstance().getResourceIndicesMutable().add(RESOURCE_INDEX_NAME);
            ResourceProvider provider = new ResourceProvider(
                SampleResource.class.getCanonicalName(),
                RESOURCE_INDEX_NAME,
                new SampleResourceParser()
            );
            ResourcePluginInfo.getInstance().getResourceProvidersMutable().put(RESOURCE_INDEX_NAME, provider);

            Thread.sleep(1000);
            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sample"));
        }

        // Update sample resource (admin should be able to update resource)
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResourceUpdated = "{\"name\":\"sampleUpdated\"}";
            TestRestClient.HttpResponse updateResponse = client.postJson(
                SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
        }

        // resource should be visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Thread.sleep(1000);
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // resource should not be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(0));
        }

        // shared_with_user should not be able to share admin's resource with itself
        // Only admins and owners can share/revoke access at the moment
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.postJson(SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId, shareWithPayload());
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("error").get("root_cause").get(0).get("reason").asText(),
                containsString("User " + SHARED_WITH_USER.getName() + " is not authorized")
            );
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);

            TestRestClient.HttpResponse response = client.postJson(SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId, shareWithPayload());
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(
                response.bodyAsJsonNode().get("share_with").get(SampleResourceScope.PUBLIC.value()).get("users").get(0).asText(),
                containsString(SHARED_WITH_USER.getName())
            );
        }

        // resource should now be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sampleUpdated"));

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
        }

        // resource is still visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);
            TestRestClient.HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload()
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("share_with").size(), equalTo(0));
        }

        // get sample resource with shared_with_user, user no longer has access to resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(0));
        }

        // delete sample resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // delete sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // corresponding entry should be removed from resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to delete the resource sharing entry manually
            TestRestClient.HttpResponse response = client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc/" + resourceSharingDocId);
            response.assertStatusCode(HttpStatus.SC_OK);

            Thread.sleep(1000);
            response = client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(0));
        }

        // get sample resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }

        // get sample resource with admin
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }
    }
}
