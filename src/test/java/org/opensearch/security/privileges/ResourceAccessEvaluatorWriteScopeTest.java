/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Scoping rules for governing raw document writes. The point of these is that turning write governance on must not
 * change how writes are authorized on any index that is not workspace-onboarded.
 */
@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("unchecked")
public class ResourceAccessEvaluatorWriteScopeTest {

    /** Workspace-onboarded: protected and declares a workspaces field. */
    private static final String WORKSPACE_INDEX = ".kibana";
    /** Plugin-owned resource index that opts out of workspaces. */
    private static final String PLUGIN_INDEX = ".sample_resource";
    private static final String UNPROTECTED_INDEX = "some-other-index";

    @Mock
    private ResourceAccessHandler resourceAccessHandler;
    @Mock
    private ResourcePluginInfo resourcePluginInfo;

    private OpensearchDynamicSetting<Boolean> featureEnabled;
    private OpensearchDynamicSetting<List<String>> protectedTypes;

    @Before
    public void setup() {
        featureEnabled = mock(OpensearchDynamicSetting.class);
        protectedTypes = mock(OpensearchDynamicSetting.class);
        lenient().when(featureEnabled.getDynamicSettingValue()).thenReturn(true);
        lenient().when(protectedTypes.getDynamicSettingValue()).thenReturn(List.of("workspace", "dashboard"));
        lenient().when(resourcePluginInfo.getResourceIndicesForProtectedTypes()).thenReturn(Set.of(WORKSPACE_INDEX, PLUGIN_INDEX));
        lenient().when(resourcePluginInfo.workspacesFieldForIndex(WORKSPACE_INDEX)).thenReturn("workspaces");
        lenient().when(resourcePluginInfo.workspacesFieldForIndex(PLUGIN_INDEX)).thenReturn(null);
    }

    private ResourceAccessEvaluator evaluator(boolean writeGovernanceEnabled) {
        return new ResourceAccessEvaluator(
            resourcePluginInfo,
            resourceAccessHandler,
            featureEnabled,
            protectedTypes,
            writeGovernanceEnabled
        );
    }

    @Test
    public void writesAreEvaluatedOnAWorkspaceOnboardedIndex() {
        ResourceAccessEvaluator evaluator = evaluator(true);

        assertTrue(evaluator.shouldEvaluate(new IndexRequest(WORKSPACE_INDEX).id("doc-1")));
        assertTrue(evaluator.shouldEvaluate(new UpdateRequest(WORKSPACE_INDEX, "doc-1")));
        assertTrue(evaluator.shouldEvaluate(new DeleteRequest(WORKSPACE_INDEX, "doc-1")));
    }

    @Test
    public void writesAreNotEvaluatedWhenGovernanceIsOff() {
        // Default state: the kill switch keeps writes behaving exactly as before.
        ResourceAccessEvaluator evaluator = evaluator(false);

        assertFalse(evaluator.shouldEvaluate(new IndexRequest(WORKSPACE_INDEX).id("doc-1")));
        assertFalse(evaluator.shouldEvaluate(new UpdateRequest(WORKSPACE_INDEX, "doc-1")));
        assertFalse(evaluator.shouldEvaluate(new DeleteRequest(WORKSPACE_INDEX, "doc-1")));
    }

    @Test
    public void writesOnAPluginOwnedResourceIndexAreLeftAlone() {
        // The index is protected but declares no workspaces field, so its writes stay plain index operations. This is
        // what keeps existing resource-sharing plugins unaffected.
        ResourceAccessEvaluator evaluator = evaluator(true);

        assertFalse(evaluator.shouldEvaluate(new IndexRequest(PLUGIN_INDEX).id("doc-1")));
        assertFalse(evaluator.shouldEvaluate(new UpdateRequest(PLUGIN_INDEX, "doc-1")));
        assertFalse(evaluator.shouldEvaluate(new DeleteRequest(PLUGIN_INDEX, "doc-1")));
    }

    @Test
    public void writesOnAnUnprotectedIndexAreLeftAlone() {
        ResourceAccessEvaluator evaluator = evaluator(true);

        assertFalse(evaluator.shouldEvaluate(new IndexRequest(UNPROTECTED_INDEX).id("doc-1")));
    }

    @Test
    public void writesWithoutADocumentIdAreLeftAlone() {
        // An auto-generated id means the document cannot have a sharing record yet.
        ResourceAccessEvaluator evaluator = evaluator(true);

        assertFalse(evaluator.shouldEvaluate(new IndexRequest(WORKSPACE_INDEX)));
    }

    @Test
    public void writesAreNotEvaluatedWhenResourceSharingIsDisabled() {
        when(featureEnabled.getDynamicSettingValue()).thenReturn(false);
        ResourceAccessEvaluator evaluator = evaluator(true);

        assertFalse(evaluator.shouldEvaluate(new IndexRequest(WORKSPACE_INDEX).id("doc-1")));
    }

    @Test
    public void getRequestsRemainExcluded() {
        // Reads are governed by DLS, not by this evaluator, regardless of write governance.
        ResourceAccessEvaluator evaluator = evaluator(true);

        assertFalse(evaluator.shouldEvaluate(new GetRequest(WORKSPACE_INDEX, "doc-1")));
    }
}
