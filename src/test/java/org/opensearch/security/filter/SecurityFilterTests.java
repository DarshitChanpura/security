/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.filter;

import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.google.common.collect.ImmutableSet;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.configuration.DlsFlsRequestValve;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.ResourceAccessEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@LuceneTestCase.SuppressSysoutChecks(bugUrl = "Parameterized thread pool tests initialize infrastructure that logs during startup")
public class SecurityFilterTests extends LuceneTestCase {

    private final Settings settings;
    private final WildcardMatcher expected;

    public SecurityFilterTests(Settings settings, WildcardMatcher expected) {
        this.settings = settings;
        this.expected = expected;
    }

    @ParametersFactory
    public static Collection<Object[]> data() {
        return Arrays.asList(
            new Object[][] {
                { Settings.EMPTY, WildcardMatcher.NONE },
                {
                    Settings.builder().putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2").build(),
                    WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2")) },
                {
                    Settings.builder()
                        .putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2", "immutable2")
                        .build(),
                    WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2")) }, }
        );
    }

    @Test
    public void testImmutableIndicesWildcardMatcher() {
        final SecurityFilter filter = new SecurityFilter(
            settings,
            mock(PrivilegesConfiguration.class),
            mock(AdminDNs.class),
            mock(DlsFlsRequestValve.class),
            mock(AuditLog.class),
            mock(ThreadPool.class),
            mock(ClusterService.class),
            mock(CompatConfig.class),
            mock(XFFResolver.class),
            mock(ResourceAccessEvaluator.class)
        );
        assertThat(expected, equalTo(filter.getImmutableIndicesMatcher()));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnexepectedCausesAreNotSendToCallers() {
        // Setup
        final AuditLog auditLog = mock(AuditLog.class);
        when(auditLog.getComplianceConfig()).thenThrow(new RuntimeException("ABC!"));
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "mock").build());

        try {
            final SecurityFilter filter = new SecurityFilter(
                settings,
                mock(PrivilegesConfiguration.class),
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                auditLog,
                threadPool,
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(XFFResolver.class),
                mock(ResourceAccessEvaluator.class)
            );

            // Act
            filter.apply(null, null, null, ActionRequestMetadata.empty(), listener, null);

            // Verify
            verify(auditLog).getComplianceConfig(); // Make sure the exception was thrown

            final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
            verify(listener).onFailure(cap.capture());

            assertThat("The cause should never be included as it will leak to callers", cap.getValue().getCause(), nullValue());
            assertThat(
                "Make sure the cause exception wasn't toStringed in the method",
                cap.getValue().getMessage(),
                not(containsString("ABC!"))
            );

            verifyNoMoreInteractions(auditLog, listener);
        } finally {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }

    /**
     * A positive resource decision early-returns in apply0 before {@code eval.evaluate(context)} is reached, and the
     * Dashboards multi-tenancy handler runs inside that evaluate call. So governing a raw document write on a
     * multi-tenancy cluster skips the tenant index rewrite, which is a tenant isolation failure rather than a missing
     * check. This pins the ordering so the bypass cannot be reintroduced silently once the two are made to compose.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void resourceAccessPathBypassesThePrivilegesEvaluatorAndSoTheMultiTenancyHandler() {
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "mock").build());
        try {
            final PrivilegesEvaluator privilegesEvaluator = mock(PrivilegesEvaluator.class);
            when(privilegesEvaluator.createContext(any(), any(), any(), any(), any())).thenReturn(mock(PrivilegesEvaluationContext.class));
            final PrivilegesConfiguration privilegesConfiguration = mock(PrivilegesConfiguration.class);
            when(privilegesConfiguration.privilegesEvaluator()).thenReturn(privilegesEvaluator);

            final ResourceAccessEvaluator resourceAccessEvaluator = mock(ResourceAccessEvaluator.class);
            when(resourceAccessEvaluator.shouldEvaluate(any())).thenReturn(true);

            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("someone"));
            // Pre-set so ThreadContextUserInfo short-circuits instead of dereferencing the mocked context.
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, "someone||||");

            final SecurityFilter filter = new SecurityFilter(
                settings,
                privilegesConfiguration,
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                mock(AuditLog.class),
                threadPool,
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(XFFResolver.class),
                resourceAccessEvaluator
            );

            final IndexRequest request = new IndexRequest(".kibana").id("dashboard:one");
            final ActionListener<ActionResponse> listener = mock(ActionListener.class);
            filter.apply(null, "indices:data/write/index", request, ActionRequestMetadata.empty(), listener, null);

            // Nothing bailed out early: no failure was reported to the caller.
            verify(listener, never()).onFailure(any());

            // The resource path ran.
            verify(resourceAccessEvaluator).evaluateAsync(any(), any(), any());
            // And the normal evaluation, which is where the multi-tenancy handler lives, did not.
            verify(privilegesEvaluator, never()).evaluate(any());
        } finally {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }
}
