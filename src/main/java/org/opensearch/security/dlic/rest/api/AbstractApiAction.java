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
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.CheckedSupplier;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import com.flipkart.zjsonpatch.JsonPatchApplicationException;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.conflict;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.api.Responses.payload;

/**
 * Generic action handler class for APIs in security plugin
 */
public abstract class AbstractApiAction extends BaseRestHandler {

    private final static Logger LOGGER = LogManager.getLogger(AbstractApiAction.class);

    private final static Set<String> supportedPatchOperations = Set.of("add", "replace", "remove");

    private final static String supportedPatchOperationsAsString = String.join(",", supportedPatchOperations);

    protected final ClusterService clusterService;

    protected final ThreadPool threadPool;

    private Map<Method, RequestHandler> requestHandlers;

    protected final RequestHandler.RequestHandlersBuilder requestHandlersBuilder;

    protected final EndpointValidator endpointValidator;

    protected final Endpoint endpoint;

    protected final SecurityApiDependencies securityApiDependencies;

    protected AbstractApiAction(
        final Endpoint endpoint,
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super();
        this.endpoint = endpoint;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.securityApiDependencies = securityApiDependencies;
        this.requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        this.requestHandlersBuilder.configureRequestHandlers(this::buildDefaultRequestHandlers);
        this.endpointValidator = createEndpointValidator();
    }

    protected void buildDefaultRequestHandlers(final RequestHandler.RequestHandlersBuilder builder) {
        builder.withAccessHandler(request -> securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint))
            .add(Method.POST, methodNotImplementedHandler)
            .add(Method.PATCH, methodNotImplementedHandler)
            .add(Method.GET, methodNotImplementedHandler)
            .add(Method.PUT, methodNotImplementedHandler)
            .add(Method.DELETE, methodNotImplementedHandler);
    }

    protected abstract ValidationResult<?> processDeleteRequest(final RestRequest request) throws IOException;

    protected abstract ValidationResult<?> processGetRequest(final RestRequest request) throws IOException;

    protected abstract ValidationResult<?> processPatchRequest(final RestRequest request) throws IOException;

    protected abstract ValidationResult<?> processPutRequest(final RestRequest request) throws IOException;

    protected final ValidationResult<JsonNode> withPatchRequestContent(final RestRequest request) {
        try {
            final var parsedPatchRequestContent = Utils.toJsonNode(request.content().utf8ToString());
            if (!(parsedPatchRequestContent instanceof ArrayNode)) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Wrong request body"));
            }
            final var operations = patchOperations(parsedPatchRequestContent);
            if (operations.isEmpty()) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Wrong request body"));
            }
            for (final var patchOperation : operations) {
                if (!supportedPatchOperations.contains(patchOperation)) {
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage(
                            "Unsupported patch operation: " + patchOperation + ". Supported are: " + supportedPatchOperationsAsString
                        )
                    );
                }
            }
            return ValidationResult.success(parsedPatchRequestContent);
        } catch (final IOException e) {
            LOGGER.debug("Error while parsing JSON patch", e);
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Error in JSON patch: " + e.getMessage()));
        }
    }

    <T> ValidationResult<T> withJsonPatchException(final CheckedSupplier<ValidationResult<T>, IOException> action) throws IOException {
        try {
            return action.get();
        } catch (final JsonPatchApplicationException e) {
            LOGGER.debug("Error while applying JSON patch", e);
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(e.getMessage()));
        }
    }

    protected final Set<String> patchOperations(final JsonNode patchRequestContent) {
        final var operations = ImmutableSet.<String>builder();
        for (final JsonNode node : patchRequestContent) {
            if (node.has("op")) operations.add(node.get("op").asText());
        }
        return operations.build();
    }

    protected final Set<String> patchEntityNames(final JsonNode patchRequestContent) {
        final var patchedResourceNames = ImmutableSet.<String>builder();
        for (final JsonNode node : patchRequestContent) {
            if (node.has("path")) {
                final var s = JsonPointer.compile(node.get("path").asText());
                patchedResourceNames.add(s.getMatchingProperty());
            }
        }
        return patchedResourceNames.build();
    }

    protected final ValidationResult<Pair<User, TransportAddress>> withUserAndRemoteAddress() {
        final var userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
        if (userAndRemoteAddress.getLeft() == null) {
            return ValidationResult.error(RestStatus.UNAUTHORIZED, payload(RestStatus.UNAUTHORIZED, "Unauthorized"));
        }
        return ValidationResult.success(userAndRemoteAddress);
    }

    protected EndpointValidator createEndpointValidator() {
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
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }

    // Over-ride this method check for any specific index names
    protected boolean ensureIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(securityApiDependencies.securityIndexName());
    }

    abstract static class OnSucessActionListener<Response> implements ActionListener<Response> {

        private final RestChannel channel;

        public OnSucessActionListener(RestChannel channel) {
            super();
            this.channel = channel;
        }

        @Override
        public final void onFailure(Exception e) {
            if (ExceptionsHelper.unwrapCause(e) instanceof VersionConflictEngineException) {
                conflict(channel, e.getMessage());
            } else {
                internalServerError(channel, "Error " + e.getMessage());
            }
        }

    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        // consume all parameters first so we can return a correct HTTP status,
        // not 400
        consumeParameters(request);

        // check if .opendistro_security index has been initialized
        if (!ensureIndexExists()) {
            return channel -> internalServerError(channel, RequestContentValidator.ValidationError.SECURITY_NOT_INITIALIZED.message());
        }

        // check if request is authorized
        final String authError = securityApiDependencies.restApiPrivilegesEvaluator().checkAccessPermissions(request, endpoint);

        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String userName = user == null ? null : user.getName();
        if (authError != null) {
            LOGGER.error("No permission to access REST API: " + authError);
            securityApiDependencies.auditLog().logMissingPrivileges(authError, userName, SecurityRequestFactory.from(request));
            // for rest request
            request.params().clear();
            return channel -> forbidden(channel, "No permission to access REST API: " + authError);
        } else {
            securityApiDependencies.auditLog().logGrantedPrivileges(userName, SecurityRequestFactory.from(request));
        }

        final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
        final Object originalOrigin = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

        return channel -> threadPool.generic().submit(() -> {
            try (StoredContext ignore = threadPool.getThreadContext().stashContext()) {
                threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                threadPool.getThreadContext()
                    .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());
                threadPool.getThreadContext()
                    .putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalUserAndRemoteAddress.getRight());
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

                requestHandlers = Optional.ofNullable(requestHandlers).orElseGet(requestHandlersBuilder::build);
                final var requestHandler = requestHandlers.getOrDefault(request.method(), methodNotImplementedHandler);
                requestHandler.handle(channel, request, client);
            } catch (Exception e) {
                LOGGER.error("Error processing request {}", request, e);
                try {
                    channel.sendResponse(new BytesRestResponse(channel, e));
                } catch (IOException ioe) {
                    throw ExceptionsHelper.convertToOpenSearchException(e);
                }
            }
        });
    }

    protected abstract void consumeParameters(final RestRequest request);

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

    @Override
    public boolean canTripCircuitBreaker() {
        return false;
    }

}
