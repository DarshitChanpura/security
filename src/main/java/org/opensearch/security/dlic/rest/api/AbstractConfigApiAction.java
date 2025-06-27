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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentHelper;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import com.flipkart.zjsonpatch.JsonDiff;
import com.flipkart.zjsonpatch.JsonPatch;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.withIOException;

/**
 * Abstract action handler class for security config APIs
 */
public abstract class AbstractConfigApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(AbstractConfigApiAction.class);

    protected AbstractConfigApiAction(
        Endpoint endpoint,
        ClusterService clusterService,
        ThreadPool threadPool,
        SecurityApiDependencies securityApiDependencies
    ) {
        super(endpoint, clusterService, threadPool, securityApiDependencies);
    }

    @Override
    public void buildDefaultRequestHandlers(final RequestHandler.RequestHandlersBuilder builder) {
        builder.withAccessHandler(request -> securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint))
            .withSaveOrUpdateConfigurationHandler(this::saveOrUpdateConfiguration)
            .add(Method.POST, methodNotImplementedHandler)
            .add(Method.PATCH, methodNotImplementedHandler)
            .onGetRequest(this::processGetRequest)
            .onChangeRequest(Method.DELETE, this::processDeleteRequest)
            .onChangeRequest(Method.PUT, this::processPutRequest);
    }

    protected final ValidationResult<SecurityConfiguration> processDeleteRequest(final RestRequest request) throws IOException {
        return endpointValidator.withRequiredEntityName(nameParam(request))
            .map(entityName -> loadConfiguration(entityName, false))
            .map(endpointValidator::onConfigDelete)
            .map(this::removeEntityFromConfig);
    }

    protected final ValidationResult<SecurityConfiguration> removeEntityFromConfig(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        configuration.remove(securityConfiguration.entityName());
        return ValidationResult.success(securityConfiguration);
    }

    protected final ValidationResult<SecurityConfiguration> processGetRequest(final RestRequest request) throws IOException {
        return loadConfiguration(getConfigType(), true, true).map(
            configuration -> ValidationResult.success(SecurityConfiguration.of(nameParam(request), configuration))
        ).map(endpointValidator::onConfigLoad).map(securityConfiguration -> securityConfiguration.maybeEntityName().map(entityName -> {
            securityConfiguration.configuration().removeOthers(entityName);
            return ValidationResult.success(securityConfiguration);
        }).orElse(ValidationResult.success(securityConfiguration)));
    }

    /**
     * Process patch requests for all types of configuration, which can be one entity in the URI or a list of entities in the request body.
     **/
    protected final ValidationResult<SecurityConfiguration> processPatchRequest(final RestRequest request) throws IOException {
        return loadConfiguration(nameParam(request), false).map(
            securityConfiguration -> withPatchRequestContent(request).map(
                patchContent -> securityConfiguration.maybeEntityName()
                    .map(entityName -> patchEntity(request, patchContent, securityConfiguration))
                    .orElseGet(() -> patchEntities(request, patchContent, securityConfiguration))
            )
        );
    }

    protected final ValidationResult<SecurityConfiguration> patchEntity(
        final RestRequest request,
        final JsonNode patchContent,
        final SecurityConfiguration securityConfiguration
    ) {
        final var entityName = securityConfiguration.entityName();
        final var configuration = securityConfiguration.configuration();
        return withIOException(
            () -> endpointValidator.isAllowedToChangeImmutableEntity(securityConfiguration)
                .map(endpointValidator::entityExists)
                .map(ignore -> {
                    final var configurationAsJson = (ObjectNode) Utils.convertJsonToJackson(configuration, true);
                    final var entityAsJson = (ObjectNode) configurationAsJson.get(entityName);
                    return withJsonPatchException(
                        () -> endpointValidator.createRequestContentValidator(entityName)
                            .validate(request, JsonPatch.apply(patchContent, entityAsJson), configurationAsJson.get(entityName))
                            .map(
                                patchedEntity -> endpointValidator.onConfigChange(
                                    SecurityConfiguration.of(patchedEntity, entityName, configuration)
                                ).map(sc -> ValidationResult.success(patchedEntity))
                            )
                            .map(patchedEntity -> {
                                final var updatedConfigurationAsJson = configurationAsJson.deepCopy().set(entityName, patchedEntity);
                                return ValidationResult.success(
                                    SecurityConfiguration.of(
                                        entityName,
                                        SecurityDynamicConfiguration.fromNode(
                                            updatedConfigurationAsJson,
                                            configuration.getCType(),
                                            configuration.getVersion(),
                                            configuration.getSeqNo(),
                                            configuration.getPrimaryTerm()
                                        )
                                    )
                                );
                            })
                    );
                })
        );
    }

    protected ValidationResult<SecurityConfiguration> patchEntities(
        final RestRequest request,
        final JsonNode patchContent,
        final SecurityConfiguration securityConfiguration
    ) {
        final var configuration = securityConfiguration.configuration();
        final var configurationAsJson = (ObjectNode) Utils.convertJsonToJackson(configuration, true);
        return withIOException(() -> withJsonPatchException(() -> {
            final var patchedConfigurationAsJson = JsonPatch.apply(patchContent, configurationAsJson);
            JsonNode patch = JsonDiff.asJson(configurationAsJson, patchedConfigurationAsJson);
            if (patch.isEmpty()) {
                return ValidationResult.error(RestStatus.OK, payload(RestStatus.OK, "No updates required"));
            }
            for (final var entityName : patchEntityNames(patchContent)) {
                final var beforePatchEntity = configurationAsJson.get(entityName);
                final var patchedEntity = patchedConfigurationAsJson.get(entityName);
                // verify we can process existing or updated entities
                if (beforePatchEntity != null && !Objects.equals(beforePatchEntity, patchedEntity)) {
                    final var checkEntityCanBeProcess = endpointValidator.isAllowedToChangeImmutableEntity(
                        SecurityConfiguration.of(entityName, configuration)
                    );
                    if (!checkEntityCanBeProcess.isValid()) {
                        return checkEntityCanBeProcess;
                    }
                }
                // entity removed no need to process patched content
                if (patchedEntity == null) {
                    continue;
                }
                // create or update case of the entity. we need to verify new JSON configuration for them
                if ((beforePatchEntity == null) || !Objects.equals(beforePatchEntity, patchedEntity)) {
                    final var requestCheck = endpointValidator.createRequestContentValidator(entityName).validate(request, patchedEntity);
                    if (!requestCheck.isValid()) {
                        return ValidationResult.error(requestCheck.status(), requestCheck.errorMessage());
                    }
                }
                // verify new JSON content for each entity using same set of validator we use for PUT, PATCH and DELETE
                final var additionalValidatorCheck = endpointValidator.onConfigChange(
                    SecurityConfiguration.of(patchedEntity, entityName, configuration)
                );
                if (!additionalValidatorCheck.isValid()) {
                    return additionalValidatorCheck;
                }
            }
            return ValidationResult.success(
                SecurityConfiguration.of(
                    null,// there is no entity name in case of patch, since there could be more the one diff entity within configuration
                    SecurityDynamicConfiguration.fromNode(
                        patchedConfigurationAsJson,
                        configuration.getCType(),
                        configuration.getVersion(),
                        configuration.getSeqNo(),
                        configuration.getPrimaryTerm()
                    )
                )
            );
        }));
    }

    protected final ValidationResult<SecurityConfiguration> processPutRequest(final RestRequest request) throws IOException {
        return processPutRequest(nameParam(request), request);
    }

    protected final ValidationResult<SecurityConfiguration> processPutRequest(final String entityName, final RestRequest request)
        throws IOException {
        return endpointValidator.withRequiredEntityName(entityName)
            .map(ignore -> loadConfigurationWithRequestContent(entityName, request))
            .map(endpointValidator::onConfigChange)
            .map(this::addEntityToConfig);
    }

    protected final ValidationResult<SecurityConfiguration> addEntityToConfig(final SecurityConfiguration securityConfiguration)
        throws IOException {
        final var configuration = securityConfiguration.configuration();
        final var entityObjectConfig = Utils.toConfigObject(securityConfiguration.requestContent(), configuration.getImplementingClass());
        configuration.putCObject(securityConfiguration.entityName(), entityObjectConfig);
        return ValidationResult.success(securityConfiguration);
    }

    final void saveOrUpdateConfiguration(
        final Client client,
        final SecurityDynamicConfiguration<?> configuration,
        final OnSucessActionListener<IndexResponse> onSucessActionListener
    ) {
        saveAndUpdateConfigsAsync(securityApiDependencies, client, getConfigType(), configuration, onSucessActionListener);
    }

    protected final String nameParam(final RestRequest request) {
        final String name = request.param("name");
        if (Strings.isNullOrEmpty(name)) {
            return null;
        }
        return name;
    }

    protected final ValidationResult<SecurityConfiguration> loadConfigurationWithRequestContent(
        final String entityName,
        final RestRequest request
    ) throws IOException {
        return endpointValidator.createRequestContentValidator()
            .validate(request)
            .map(
                content -> loadConfiguration(getConfigType(), false, false).map(
                    configuration -> ValidationResult.success(SecurityConfiguration.of(content, entityName, configuration))
                )
            );
    }

    protected final ValidationResult<SecurityConfiguration> loadConfiguration(final String entityName, final boolean logComplianceEvent)
        throws IOException {
        return loadConfiguration(getConfigType(), false, logComplianceEvent).map(
            configuration -> ValidationResult.success(SecurityConfiguration.of(entityName, configuration))
        );
    }

    protected ValidationResult<SecurityDynamicConfiguration<?>> loadConfiguration(
        final CType<?> cType,
        boolean omitSensitiveData,
        final boolean logComplianceEvent
    ) {
        SecurityDynamicConfiguration<?> configuration;
        if (omitSensitiveData) {
            configuration = loadAndRedact(cType, logComplianceEvent);
        } else {
            configuration = load(cType, logComplianceEvent);
        }
        if (configuration.getSeqNo() < 0) {

            return ValidationResult.error(
                RestStatus.FORBIDDEN,
                forbiddenMessage(
                    "Security index need to be updated to support '" + getConfigType().toLCString() + "'. Use SecurityAdmin to populate."
                )
            );
        }
        if (omitSensitiveData) {
            if (!securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint)) {
                configuration.removeHidden();
            }
            configuration.clearHashes();
            configuration.set_meta(null);
        }
        return ValidationResult.success(configuration);
    }

    protected EndpointValidator createEndpointValidator() {
        // Pessimistic Validator. All CRUD actions are forbidden
        return new EndpointValidator() {
            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) throws IOException {

                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) throws IOException {

                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {

                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }

    protected abstract CType<?> getConfigType();

    protected final SecurityDynamicConfiguration<?> load(final CType<?> config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = securityApiDependencies.configurationRepository()
            .getConfigurationsFromIndex(List.of(config), logComplianceEvent)
            .get(config)
            .deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    protected final SecurityDynamicConfiguration<?> loadAndRedact(final CType<?> config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = securityApiDependencies.configurationRepository()
            .getConfigurationsFromIndex(List.of(config), logComplianceEvent)
            .get(config)
            .deepCloneWithRedaction();
        return DynamicConfigFactory.addStatics(loaded);
    }

    protected boolean ensureIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(securityApiDependencies.securityIndexName());
    }

    public static ActionFuture<IndexResponse> saveAndUpdateConfigs(
        final SecurityApiDependencies dependencies,
        final Client client,
        final CType<?> cType,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        final var request = createIndexRequestForConfig(dependencies, cType, configuration);
        return client.index(request);
    }

    public static void saveAndUpdateConfigsAsync(
        final SecurityApiDependencies dependencies,
        final Client client,
        final CType<?> cType,
        final SecurityDynamicConfiguration<?> configuration,
        final ActionListener<IndexResponse> actionListener
    ) {
        final var ir = createIndexRequestForConfig(dependencies, cType, configuration);
        client.index(ir, new ConfigUpdatingActionListener<>(new String[] { cType.toLCString() }, client, actionListener));
    }

    private static IndexRequest createIndexRequestForConfig(
        final SecurityApiDependencies dependencies,
        final CType<?> cType,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        configuration.removeStatic();
        final BytesReference content;
        try {
            content = XContentHelper.toXContent(configuration, XContentType.JSON, ToXContent.EMPTY_PARAMS, false);
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }

        return new IndexRequest(dependencies.securityIndexName()).id(cType.toLCString())
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .setIfSeqNo(configuration.getSeqNo())
            .setIfPrimaryTerm(configuration.getPrimaryTerm())
            .source(cType.toLCString(), content);
    }

    protected static class ConfigUpdatingActionListener<Response> implements ActionListener<Response> {
        private final String[] cTypes;
        private final Client client;
        private final ActionListener<Response> delegate;

        public ConfigUpdatingActionListener(String[] cTypes, Client client, ActionListener<Response> delegate) {
            this.cTypes = Objects.requireNonNull(cTypes, "cTypes must not be null");
            this.client = Objects.requireNonNull(client, "client must not be null");
            this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        }

        @Override
        public void onResponse(Response response) {

            final ConfigUpdateRequest cur = new ConfigUpdateRequest(cTypes);

            client.execute(ConfigUpdateAction.INSTANCE, cur, new ActionListener<ConfigUpdateResponse>() {
                @Override
                public void onResponse(final ConfigUpdateResponse ur) {
                    if (ur.hasFailures()) {
                        delegate.onFailure(ur.failures().get(0));
                        return;
                    }
                    delegate.onResponse(response);
                }

                @Override
                public void onFailure(final Exception e) {
                    delegate.onFailure(e);
                }
            });

        }

        @Override
        public void onFailure(Exception e) {
            delegate.onFailure(e);
        }

    }

    /**
     * Consume all defined parameters for the request. Before we handle the
     * request in subclasses where we actually need the parameter, some global
     * checks are performed, e.g. check whether the .security_index index exists. Thus, the
     * parameter(s) have not been consumed, and OpenSearch will always return a 400 with
     * an internal error message.
     *
     * @param request
     */
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
    }

}
