/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.client.Client;

import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;

/**
 * End-to-end verification of the "secured view" access binding: an index permission marked
 * {@code restrict_to_alias} authorizes access only <b>through the alias</b>, and does <b>not</b> confer access
 * to the alias's backing concrete index when that index is requested directly.
 * <p>
 * The corpus is a single backing index {@link #BACKING_INDEX} with an alias {@link #VIEW_ALIAS} that filters
 * to the cardiology department. Two users are granted read on the alias:
 * <ul>
 *   <li>{@link #VIEW_USER} — granted with {@code restrict_to_alias: true}. Can read the alias; must be FORBIDDEN
 *       on the backing index.</li>
 *   <li>{@link #INHERIT_USER} — granted the same alias WITHOUT the flag (historical behavior). Can read both the
 *       alias and the backing index — the control proving the flag is what makes the difference.</li>
 * </ul>
 * This exercises both authorization paths: the precomputed/stateful path and the per-request static path.
 */
public class SecuredViewRestrictToAliasIntegrationTest {

    private static final String BACKING_INDEX = "patients";
    private static final String VIEW_ALIAS = "cardiology_view";
    private static final String DEPT_FIELD = "dept";
    private static final String VISIBLE_DEPT = "cardiology";
    private static final String RESTRICTED_DEPT = "oncology";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    // Granted ONLY the alias, as a secured view: alias reachable, backing index must NOT be.
    static final TestSecurityConfig.User VIEW_USER = new TestSecurityConfig.User("view_user").roles(
        new TestSecurityConfig.Role("secured_view_role").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .restrictToAlias(true)
            .on(VIEW_ALIAS)
    );

    // Granted the same alias without the flag: historical inheritance -> backing index reachable (control).
    static final TestSecurityConfig.User INHERIT_USER = new TestSecurityConfig.User("inherit_user").roles(
        new TestSecurityConfig.Role("inherit_alias_role").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .on(VIEW_ALIAS)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        // The nextgen (v4) privilege evaluator preserves the alias name in the resolved indices, so an access
        // through the alias is distinguishable from a direct request for the backing index. This distinction is
        // what restrict_to_alias relies on; the legacy evaluator expands the alias to concrete backing names
        // before the check, so it cannot support this feature (see the design doc's scope note).
        .privilegesEvaluationType("v4")
        .users(ADMIN_USER, VIEW_USER, INHERIT_USER)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            for (int i = 0; i < 5; i++) {
                client.prepareIndex(BACKING_INDEX).setRefreshPolicy(IMMEDIATE).setSource(DEPT_FIELD, VISIBLE_DEPT).get();
            }
            for (int i = 0; i < 7; i++) {
                client.prepareIndex(BACKING_INDEX).setRefreshPolicy(IMMEDIATE).setSource(DEPT_FIELD, RESTRICTED_DEPT).get();
            }
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).index(BACKING_INDEX)
                            .alias(VIEW_ALIAS)
                            .filter(QueryBuilders.termQuery(DEPT_FIELD, VISIBLE_DEPT))
                    )
                )
                .actionGet();
        }
    }

    private SearchResponse searchAs(TestSecurityConfig.User user, String target) throws Exception {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(user)) {
            SearchRequest request = new SearchRequest(target);
            request.source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(50));
            return client.search(request, DEFAULT);
        }
    }

    @Test
    public void securedView_userCanReadThroughAlias() throws Exception {
        // The alias filters to cardiology, so the view user sees exactly the 5 visible docs.
        SearchResponse response = searchAs(VIEW_USER, VIEW_ALIAS);
        assertThat(response, isSuccessfulSearchResponse());
        assertThat(response, numberOfTotalHitsIsEqualTo(5));
    }

    @Test
    public void securedView_userCannotReachBackingIndexDirectly() throws Exception {
        // The whole point: a grant on the alias with restrict_to_alias must NOT authorize the backing index.
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(VIEW_USER)) {
            SearchRequest request = new SearchRequest(BACKING_INDEX);
            request.source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(50));
            assertThatThrownBy(() -> client.search(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void controlUser_withoutFlag_canReachBackingIndex() throws Exception {
        // Control: the same alias grant WITHOUT restrict_to_alias still reaches the backing index (unchanged
        // historical behavior), so the whole backing corpus (12 docs) is visible.
        SearchResponse viaAlias = searchAs(INHERIT_USER, VIEW_ALIAS);
        assertThat(viaAlias, isSuccessfulSearchResponse());
        assertThat(viaAlias, numberOfTotalHitsIsEqualTo(5));

        SearchResponse viaBacking = searchAs(INHERIT_USER, BACKING_INDEX);
        assertThat(viaBacking, isSuccessfulSearchResponse());
        assertThat(viaBacking, numberOfTotalHitsIsEqualTo(12));
    }

    private static void assertThat(SearchResponse response, org.hamcrest.Matcher<SearchResponse> matcher) {
        org.hamcrest.MatcherAssert.assertThat(response, matcher);
    }
}
