/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviour;
import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviourRequest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class MockBehaviorRequestBuilder extends EidMockRequestBuilder<MockBehaviorRequestBuilder> {
    public static final ObjectMapper MAPPER = new ObjectMapper();

    public MockBehaviorRequestBuilder withBehavior(String requestUri, EidAuthMockBehaviour behavior) {
        EidAuthMockBehaviourRequest behaviourRequest = new EidAuthMockBehaviourRequest().behaviour(behavior);
        if (requestUri != null &&  !requestUri.isEmpty()) {
            behaviourRequest.requestUri(requestUri);
        }
        return withUrl(createUrl())
            .withHeader("accept", "application/json")
            .withHeader("content-type", "application/json")
            .withJsonBody((tools.jackson.databind.node.ObjectNode) MAPPER.convertValue(behaviourRequest, JsonNode.class));
    }

    public MockBehaviorRequestBuilder withBehavior(EidAuthMockBehaviour behavior) {
        return withBehavior(null, behavior);
    }

    @Override
    String getPath() {
        return "behaviour";
    }
}
