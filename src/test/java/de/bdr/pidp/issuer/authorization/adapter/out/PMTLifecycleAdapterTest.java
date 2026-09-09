/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.PidpServiceUnavailableException;
import de.bdr.pidp.issuer.base.RevocationServiceConfiguration;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withGatewayTimeout;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withResourceNotFound;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RestClientTest({PMTLifecycleAdapter.class, RevocationServiceConfiguration.class})
class PMTLifecycleAdapterTest {

    @Autowired
    private MockRestServiceServer mockServer;

    @Autowired
    private PMTLifecycleAdapter adapter;

    @Autowired
    private RevocationServiceConfiguration configuration;

    private final DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC);
    private final JsonMapper jsonMapper = new JsonMapper();

    @Nested
    class RegisterToken {

        @Test
        void shouldRegisterToken() {
            // Given
            var tokenID = UUID.randomUUID().toString();
            var pseudonym = "pseudonym";
            var exp = Instant.parse("2050-05-07T10:00:00Z");
            var statusRef = TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF;

            mockServer.expect(requestTo(getExpectedRequestUri()))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-api-key", configuration.getApiKey()))
                .andExpect(jsonPath("tokenID").value(tokenID))
                .andExpect(jsonPath("pseudonym").value(pseudonym))
                .andExpect(jsonPath("expiration").value(formatter.format(exp)))
                .andExpect(jsonPath("statusListRef.uri").value(statusRef.uri().toString()))
                .andExpect(jsonPath("statusListRef.index").value(statusRef.index()))
                .andRespond(_ -> new MockClientHttpResponse(new byte[0], 201));

            // When
            adapter.registerToken(tokenID, pseudonym, exp, statusRef);

            // Then
            mockServer.verify();
        }

        @Test
        void shouldRegisterTokenWithoutStatusListRef() {
            // Given
            var tokenID = UUID.randomUUID().toString();
            var pseudonym = "pseudonym";
            var exp = Instant.parse("2050-05-07T10:00:00Z");

            mockServer.expect(requestTo(getExpectedRequestUri()))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-api-key", configuration.getApiKey()))
                .andExpect(jsonPath("tokenID").value(tokenID))
                .andExpect(jsonPath("pseudonym").value(pseudonym))
                .andExpect(jsonPath("expiration").value(formatter.format(exp)))
                .andExpect(jsonPath("statusListRef").doesNotExist())
                .andRespond(_ -> new MockClientHttpResponse(new byte[0], 201));

            // When
            adapter.registerToken(tokenID, pseudonym, exp, null);

            // Then
            mockServer.verify();
        }

        @Test
        void shouldThrowExceptionOnBadRequest() {
            // Given
            var tokenID = UUID.randomUUID().toString();
            var pseudonym = "pseudonym";
            var exp = Instant.parse("2050-05-07T10:00:00Z");
            var statusRef = TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF;
            mockServer.expect(requestTo(getExpectedRequestUri()))
                .andRespond(withBadRequest());

            // When, Then
            assertThatThrownBy(() -> adapter.registerToken(tokenID, pseudonym, exp, statusRef))
                .isInstanceOf(PidServerException.class)
                .hasMessage("Revocation lifecycle request rejected")
                .hasCauseInstanceOf(RestClientException.class);
        }

        @Test
        void shouldThrowExceptionOnRestClientException() {
            // Given
            var tokenID = UUID.randomUUID().toString();
            var pseudonym = "pseudonym";
            var exp = Instant.parse("2050-05-07T10:00:00Z");
            var statusRef = TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF;
            mockServer.expect(requestTo(getExpectedRequestUri()))
                .andRespond(withGatewayTimeout());

            // When, Then
            assertThatThrownBy(() -> adapter.registerToken(tokenID, pseudonym, exp, statusRef))
                .isInstanceOf(PidpServiceUnavailableException.class)
                .hasMessage("Revocation lifecycle request failed due to an unexpected error")
                .hasCauseInstanceOf(RestClientException.class);
        }

        private String getExpectedRequestUri() {
            return "%s/pid-master-token/lifecycle".formatted(
                configuration.getBaseUrl()
            );
        }
    }

    @Nested
    @ExtendWith(OutputCaptureExtension.class)
    @Isolated
    class TokenLifecycleStatus {

        @ParameterizedTest
        @EnumSource(ValidityStatus.Status.class)
        void shouldGetTokenStatus(ValidityStatus.Status status) {
            // Given
            var tokenID = UUID.randomUUID().toString();

            mockServer.expect(requestTo(getExpectedRequestUri(tokenID)))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("x-api-key", configuration.getApiKey()))
                .andRespond(withSuccess(
                    jsonMapper.writeValueAsString(new ValidityStatus(status)),
                    MediaType.APPLICATION_JSON
                ));

            // When
            var result = adapter.isTokenValid(tokenID);

            // Then
            assertThat(result).isEqualTo(switch (status) {
                case VALID -> true;
                case INVALID -> false;
            });
        }

        @Test
        void shouldNotBeValidOn404(CapturedOutput output) {
            // Given
            var tokenID = UUID.randomUUID().toString();

            mockServer.expect(requestTo(getExpectedRequestUri(tokenID)))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("x-api-key", configuration.getApiKey()))
                .andRespond(withResourceNotFound());

            // When
            var result = adapter.isTokenValid(tokenID);

            // Then
            assertThat(result).isFalse();
            assertThat(output).contains("logType=security", "Refresh token ID (jti) not found at revocation-service");
        }


        @Test
        void shouldThrowExceptionOnBadRequest() {
            // Given
            var tokenID = UUID.randomUUID().toString();
            mockServer.expect(requestTo(getExpectedRequestUri(tokenID)))
                .andRespond(withBadRequest());

            // When, Then
            assertThatThrownBy(() -> adapter.isTokenValid(tokenID))
                .isInstanceOf(PidServerException.class)
                .hasMessage("Revocation lifecycle status request rejected")
                .hasCauseInstanceOf(RestClientException.class);
        }

        @Test
        void shouldThrowExceptionOnRestClientException() {
            // Given
            var tokenID = UUID.randomUUID().toString();
            mockServer.expect(requestTo(getExpectedRequestUri(tokenID)))
                .andRespond(withGatewayTimeout());

            // When, Then
            assertThatThrownBy(() -> adapter.isTokenValid(tokenID))
                .isInstanceOf(PidpServiceUnavailableException.class)
                .hasMessage("Revocation lifecycle status request failed due to an unexpected error")
                .hasCauseInstanceOf(RestClientException.class);
        }

        private String getExpectedRequestUri(String tokenID) {
            return "%s/pid-master-token/%s/lifecycle/status".formatted(
                configuration.getBaseUrl(), tokenID
            );
        }
    }
}
