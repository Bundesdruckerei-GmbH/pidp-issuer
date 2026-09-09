/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.sls;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.core.StatusListServiceConfiguration;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClientException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withGatewayTimeout;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RestClientTest({StatusListAdapter.class, StatusListServiceConfiguration.class})
class StatusListAdapterTest {

    @Autowired
    private MockRestServiceServer mockServer;

    @Autowired
    private StatusListAdapter statusListAdapter;

    @Autowired
    private StatusListServiceConfiguration configuration;

    private final JsonMapper jsonMapper = new JsonMapper();

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void shouldGetReferences(int amount) throws JacksonException {
        // Given
        var statusReferences = List.of(
            new StatusReference("status-list-url", 4711),
            new StatusReference("status-list-url", 4712)
        );
        var references = new References(statusReferences.subList(0, amount));

        mockServer.expect(requestTo(getExpectedRequestUri(amount)))
            .andExpect(method(HttpMethod.POST))
            .andExpect(header("x-api-key", configuration.getApiKey()))
            .andRespond(withSuccess(
                jsonMapper.writeValueAsString(references),
                MediaType.APPLICATION_JSON
            ));

        // When
        var result = statusListAdapter.acquireFreeIndices(amount);

        // Then
        assertThat(result).hasSize(amount);
        for (int i = 0; i < amount; i++) {
            assertThat(result.get(i).index()).isEqualTo(statusReferences.get(i).index());
            assertThat(result.get(i).uri()).isEqualTo(statusReferences.get(i).uri());
        }
        mockServer.verify();
    }

    @Test
    void shouldNotGetReferenceOnServerError() {
        // Given
        mockServer.expect(requestTo(getExpectedRequestUri(1)))
            .andRespond(withGatewayTimeout());

        // When, Then
        assertThatThrownBy(() -> statusListAdapter.acquireFreeIndices(1))
            .isInstanceOf(PidServerException.class)
            .hasMessage("Could not acquire free index from status list service")
            .hasCauseInstanceOf(RestClientException.class);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void shouldNotGetReferenceOnInvalidValues(int amount) {
        assertThatThrownBy(() -> statusListAdapter.acquireFreeIndices(amount))
            .isInstanceOf(IllegalArgumentException.class);
    }

    private String getExpectedRequestUri(int amount) {
        return "%s/pools/%s/new-references?amount=%d".formatted(
            configuration.getBaseUrl(),
            configuration.getPoolId(),
            amount
        );
    }
}
