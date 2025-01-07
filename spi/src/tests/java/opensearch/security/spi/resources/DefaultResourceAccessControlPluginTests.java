/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package tests.java.opensearch.security.spi.resources;

public class DefaultResourceAccessControlPluginTests {
    // @Override
    // protected Collection<Class<? extends Plugin>> nodePlugins() {
    // return List.of(TestResourcePlugin.class);
    // }
    //
    // public void testGetResources() throws IOException {
    // final Client client = client();
    //
    // createIndex(SAMPLE_TEST_INDEX);
    // indexSampleDocuments();
    //
    // Set<TestResourcePlugin.TestResource> resources;
    // try (
    // DefaultResourceAccessControlExtension plugin = new DefaultResourceAccessControlExtension(
    // client,
    // internalCluster().getInstance(ThreadPool.class)
    // )
    // ) {
    // resources = plugin.getAccessibleResourcesForCurrentUser(SAMPLE_TEST_INDEX, TestResourcePlugin.TestResource.class);
    //
    // assertNotNull(resources);
    // MatcherAssert.assertThat(resources, hasSize(2));
    //
    // MatcherAssert.assertThat(resources, hasItem(hasProperty("id", is("1"))));
    // MatcherAssert.assertThat(resources, hasItem(hasProperty("id", is("2"))));
    // }
    // }
    //
    // public void testSampleResourcePluginListResources() throws IOException {
    // createIndex(SAMPLE_TEST_INDEX);
    // indexSampleDocuments();
    //
    // ResourceAccessControlPlugin racPlugin = TestResourcePlugin.GuiceHolder.getResourceService().getResourceAccessControlPlugin();
    // MatcherAssert.assertThat(racPlugin.getClass(), is(DefaultResourceAccessControlExtension.class));
    //
    // Set<TestResourcePlugin.TestResource> resources = racPlugin.getAccessibleResourcesForCurrentUser(
    // SAMPLE_TEST_INDEX,
    // TestResourcePlugin.TestResource.class
    // );
    //
    // assertNotNull(resources);
    // MatcherAssert.assertThat(resources, hasSize(2));
    // MatcherAssert.assertThat(resources, hasItem(hasProperty("id", is("1"))));
    // MatcherAssert.assertThat(resources, hasItem(hasProperty("id", is("2"))));
    // }
    //
    // public void testSampleResourcePluginCallsHasPermission() {
    //
    // ResourceAccessControlPlugin racPlugin = TestResourcePlugin.GuiceHolder.getResourceService().getResourceAccessControlPlugin();
    // MatcherAssert.assertThat(racPlugin.getClass(), is(DefaultResourceAccessControlExtension.class));
    //
    // boolean canAccess = racPlugin.hasPermission("1", SAMPLE_TEST_INDEX, null);
    //
    // MatcherAssert.assertThat(canAccess, is(true));
    //
    // }
    //
    // public void testSampleResourcePluginCallsShareWith() {
    //
    // ResourceAccessControlPlugin racPlugin = TestResourcePlugin.GuiceHolder.getResourceService().getResourceAccessControlPlugin();
    // MatcherAssert.assertThat(racPlugin.getClass(), is(DefaultResourceAccessControlExtension.class));
    //
    // ResourceSharing sharingInfo = racPlugin.shareWith("1", SAMPLE_TEST_INDEX, new ShareWith(Set.of()));
    //
    // MatcherAssert.assertThat(sharingInfo, is(nullValue()));
    // }
    //
    // public void testSampleResourcePluginCallsRevokeAccess() {
    //
    // ResourceAccessControlPlugin racPlugin = TestResourcePlugin.GuiceHolder.getResourceService().getResourceAccessControlPlugin();
    // MatcherAssert.assertThat(racPlugin.getClass(), is(DefaultResourceAccessControlExtension.class));
    //
    // ResourceSharing sharingInfo = racPlugin.revokeAccess("1", SAMPLE_TEST_INDEX, Map.of(), Set.of("some_scope"));
    //
    // MatcherAssert.assertThat(sharingInfo, is(nullValue()));
    // }
    //
    // public void testSampleResourcePluginCallsDeleteResourceSharingRecord() {
    // ResourceAccessControlPlugin racPlugin = TestResourcePlugin.GuiceHolder.getResourceService().getResourceAccessControlPlugin();
    // MatcherAssert.assertThat(racPlugin.getClass(), is(DefaultResourceAccessControlExtension.class));
    //
    // boolean recordDeleted = racPlugin.deleteResourceSharingRecord("1", SAMPLE_TEST_INDEX);
    //
    // // no record to delete
    // MatcherAssert.assertThat(recordDeleted, is(false));
    // }
    //
    // public void testSampleResourcePluginCallsDeleteAllResourceSharingRecordsForCurrentUser() {
    // ResourceAccessControlPlugin racPlugin = TestResourcePlugin.GuiceHolder.getResourceService().getResourceAccessControlPlugin();
    // MatcherAssert.assertThat(racPlugin.getClass(), is(DefaultResourceAccessControlExtension.class));
    //
    // boolean recordDeleted = racPlugin.deleteAllResourceSharingRecordsForCurrentUser();
    //
    // // no records to delete
    // MatcherAssert.assertThat(recordDeleted, is(false));
    // }
    //
    // private void indexSampleDocuments() throws IOException {
    // XContentBuilder doc1 = jsonBuilder().startObject().field("id", "1").field("name", "Test Document 1").endObject();
    //
    // XContentBuilder doc2 = jsonBuilder().startObject().field("id", "2").field("name", "Test Document 2").endObject();
    //
    // try (Client client = client()) {
    //
    // client.prepareIndex(SAMPLE_TEST_INDEX).setId("1").setSource(doc1).get();
    //
    // client.prepareIndex(SAMPLE_TEST_INDEX).setId("2").setSource(doc2).get();
    //
    // client.admin().indices().prepareRefresh(SAMPLE_TEST_INDEX).get();
    // }
    // }
}
