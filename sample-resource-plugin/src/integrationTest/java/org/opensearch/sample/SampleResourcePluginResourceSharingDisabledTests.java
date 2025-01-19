package org.opensearch.sample;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with security disabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginResourceSharingDisabledTests extends AbstractSampleResourcePluginTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
        .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, false))
        .build();

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
        }
    }

    @Test
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse pluginsResponse = client.get("_cat/plugins");
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.security.OpenSearchSecurityPlugin"));
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.sample.SampleResourcePlugin"));
        }
    }

    @Test
    public void testNoResourceRestrictions() throws Exception {
        String resourceId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = "{\"name\":\"sample\"}";
            HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
        }

        // assert that resource-sharing index doesn't exist and neither do resource-sharing APIs
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse response = client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search");
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);

            response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getBody(), containsString("no handler found for uri"));

            response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, "{}");
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getBody(), containsString("no handler found for uri"));

            response = client.postJson(SECURITY_RESOURCE_REVOKE_ENDPOINT, "{}");
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getBody(), containsString("no handler found for uri"));

            response = client.postJson(SECURITY_RESOURCE_VERIFY_ENDPOINT, "{}");
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getBody(), containsString("no handler found for uri"));
        }

        // resource should be visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {

            HttpResponse response = client.postJson(RESOURCE_INDEX_NAME + "/_search", "{\"query\" :  {\"match_all\" : {}}}");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
        }

        // resource should be visible to shared_with_user since there is no restriction and this user has * permission
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.postJson(RESOURCE_INDEX_NAME + "/_search", "{\"query\" :  {\"match_all\" : {}}}");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
        }

        // shared_with_user is able to update admin's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
            HttpResponse updateResponse = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, updatePayload);
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
        }

        // admin can see updated value
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse getResponse = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            getResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(getResponse.getBody(), containsString("sampleUpdated"));
        }

        // delete sample resource - share_with user delete admin user's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // admin can no longer see the resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse getResponse = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            getResponse.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }

    }
}
