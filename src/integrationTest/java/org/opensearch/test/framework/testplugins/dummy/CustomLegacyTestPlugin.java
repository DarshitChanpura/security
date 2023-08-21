package org.opensearch.test.framework.testplugins.dummy;

import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.NetworkPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.test.framework.testplugins.dummy.dummyaction.DummyAction;
import org.opensearch.test.framework.testplugins.dummy.dummyaction.TransportDummyAction;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class CustomLegacyTestPlugin extends Plugin implements ClusterPlugin, NetworkPlugin, ActionPlugin {

    @Override
    public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        IndexScopedSettings indexScopedSettings,
        SettingsFilter settingsFilter,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<DiscoveryNodes> nodesInCluster
    ) {

        final List<RestHandler> handlers = new ArrayList<RestHandler>(1);
        handlers.add(new LegacyRestHandler());

        return handlers;
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> actions = new ArrayList<>(1);

        actions.add(new ActionHandler<>(DummyAction.INSTANCE, TransportDummyAction.class));

        return actions;
    }
}
