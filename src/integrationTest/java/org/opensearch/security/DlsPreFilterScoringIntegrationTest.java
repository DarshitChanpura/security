/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import java.io.IOException;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchType;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;

/**
 * Verifies the DLS pre-filter scoring bridge (plugins.security.dls.pre_filter_scoring).
 * <p>
 * When enabled, filter-level DLS wraps its (DLS filter + user query) in a constant_score, so BM25
 * statistics reflect only the documents the role can read. This test asserts the two properties that
 * matter:
 * <ul>
 *   <li><b>Isolation is unchanged</b> — the restricted user still gets exactly their subset of
 *       documents (the bridge changes scoring, not which docs are returned), and cannot see the rest.</li>
 *   <li><b>Scores are visibility-independent</b> — a term that occurs only in documents the user cannot
 *       read no longer affects the score of a document the user can read. Under constant_score every
 *       visible hit scores 1.0, so relevance scores depend only on the visible subset.</li>
 * </ul>
 */
public class DlsPreFilterScoringIntegrationTest {

    private static final String INDEX = "documents";
    private static final String DEPT_FIELD = "dept";
    private static final String CONTENT_FIELD = "content";
    private static final String VISIBLE_DEPT = "cardiology";
    private static final String RESTRICTED_DEPT = "oncology";
    // Appears only in restricted documents -> inflates its corpus-wide df.
    private static final String RESTRICTED_TERM = "infarction";
    // Appears in no document at all.
    private static final String ABSENT_TERM = "zzqxkjpwvbm";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    // Restricted to cardiology via a DLS clause on the role — this is the "secured view" binding.
    static final TestSecurityConfig.User CARDIO_USER = new TestSecurityConfig.User("cardio_user").roles(
        new TestSecurityConfig.Role("cardiology_only").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"term\":{\"%s\":\"%s\"}}", DEPT_FIELD, VISIBLE_DEPT))
            .on(INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        // Turn ON the pre-filter scoring bridge, and force filter-level DLS so the bridge's
        // constant_score wrap is exercised. (In ADAPTIVE mode a simple term DLS query would take the
        // lucene-level reader path instead; the pre-filter bridge currently covers the filter-level
        // path — closing the lucene-level path's scoring is the follow-up that reuses the core
        // pre_filter filtered-statistics work.)
        .nodeSettings(Map.of("plugins.security.dls.pre_filter_scoring", true, "plugins.security.dls.mode", "filter_level"))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, CARDIO_USER)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            // 3 visible cardiology docs (none carry the restricted term themselves)...
            for (int i = 0; i < 3; i++) {
                client.prepareIndex(INDEX)
                    .setRefreshPolicy(IMMEDIATE)
                    .setSource(DEPT_FIELD, VISIBLE_DEPT, CONTENT_FIELD, "cardiology note " + i)
                    .get();
            }
            // ...many restricted docs carrying the restricted term -> high corpus-wide df...
            for (int i = 0; i < 50; i++) {
                client.prepareIndex(INDEX)
                    .setRefreshPolicy(IMMEDIATE)
                    .setSource(DEPT_FIELD, RESTRICTED_DEPT, CONTENT_FIELD, "restricted " + RESTRICTED_TERM + " " + i)
                    .get();
            }
            // ...and one visible probe doc containing BOTH the restricted term and the absent term.
            client.prepareIndex(INDEX)
                .setRefreshPolicy(IMMEDIATE)
                .setSource(DEPT_FIELD, VISIBLE_DEPT, CONTENT_FIELD, "probe " + RESTRICTED_TERM + " " + ABSENT_TERM)
                .get();
        }
    }

    private SearchResponse searchAs(RestHighLevelClient client, String matchTerm) throws IOException {
        return searchAs(client, matchTerm, null);
    }

    private SearchResponse searchAs(RestHighLevelClient client, String matchTerm, SearchType searchType) throws IOException {
        SearchRequest request = new SearchRequest(INDEX);
        if (searchType != null) {
            request.searchType(searchType);
        }
        SearchSourceBuilder source = new SearchSourceBuilder().size(20);
        if (matchTerm != null) {
            source.query(QueryBuilders.matchQuery(CONTENT_FIELD, matchTerm));
        } else {
            source.query(QueryBuilders.matchAllQuery());
        }
        request.source(source);
        return client.search(request, DEFAULT);
    }

    @Test
    public void isolationIsPreserved_userSeesOnlyCardiology() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(CARDIO_USER)) {
            // 4 cardiology docs total (3 notes + 1 probe); the 50 restricted docs must be invisible.
            SearchResponse all = searchAs(client, null);
            assertThat(all, isSuccessfulSearchResponse());
            assertThat(all, numberOfTotalHitsIsEqualTo(4));

            // The restricted term is confined to non-visible docs, so the only hit is the visible sample doc.
            SearchResponse forRestricted = searchAs(client, RESTRICTED_TERM);
            assertThat(forRestricted, isSuccessfulSearchResponse());
            assertThat(forRestricted, numberOfTotalHitsIsEqualTo(1));
        }
    }

    @Test
    public void scoresAreVisibilityIndependent_underPreFilterScoring() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(CARDIO_USER)) {
            // Sample scored for the restricted term (present in 50 non-visible docs)...
            SearchResponse restrictedResp = searchAs(client, RESTRICTED_TERM);
            SearchHit[] restrictedHits = restrictedResp.getHits().getHits();
            assertThat((double) restrictedHits.length, greaterThan(0.0));
            float restrictedScore = restrictedHits[0].getScore();

            // ...vs the same probe scored for the absent term (present nowhere).
            SearchResponse absentResp = searchAs(client, ABSENT_TERM);
            SearchHit[] absentHits = absentResp.getHits().getHits();
            assertThat((double) absentHits.length, greaterThan(0.0));
            float absentScore = absentHits[0].getScore();

            // Under constant_score both are 1.0: the df of non-visible docs never enters the score, so the
            // restricted term is indistinguishable from a term that exists nowhere. Without the bridge
            // (plain post-filter DLS) restrictedScore would be measurably below absentScore.
            assertThat(
                "restricted-term score must equal absent-term score under pre-filter scoring",
                (double) restrictedScore,
                closeTo(absentScore, 0.0001)
            );
        }
    }

    /**
     * dfs_query_then_fetch gathers term statistics in a separate DFS phase before the query phase.
     * The pre-filter wrap is applied in the query phase (onPreQueryPhase -&gt; handleSearchContext), so
     * this asserts the DFS phase also sees the wrapped query and does not reintroduce whole-shard
     * statistics: under DFS, a term confined to non-visible docs must still score the same as an
     * absent term. Guards the (otherwise only hand-verified) DFS coverage.
     */
    @Test
    public void scoresAreVisibilityIndependent_underDfsQueryThenFetch() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(CARDIO_USER)) {
            SearchResponse restrictedResp = searchAs(client, RESTRICTED_TERM, SearchType.DFS_QUERY_THEN_FETCH);
            SearchHit[] restrictedHits = restrictedResp.getHits().getHits();
            assertThat((double) restrictedHits.length, greaterThan(0.0));
            float restrictedScore = restrictedHits[0].getScore();

            SearchResponse absentResp = searchAs(client, ABSENT_TERM, SearchType.DFS_QUERY_THEN_FETCH);
            SearchHit[] absentHits = absentResp.getHits().getHits();
            assertThat((double) absentHits.length, greaterThan(0.0));
            float absentScore = absentHits[0].getScore();

            assertThat(
                "under dfs_query_then_fetch, restricted-term score must equal absent-term score",
                (double) restrictedScore,
                closeTo(absentScore, 0.0001)
            );
        }
    }
}
