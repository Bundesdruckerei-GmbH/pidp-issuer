/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import com.nimbusds.jose.EncryptionMethod;
import de.bdr.pidp.issuer.issuance.RequestUtil;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.RequestEncryptionJWKSupplier;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CredentialService;
import de.bdr.pidp.issuer.testdata.TestUtils;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.tck.MeterRegistryAssert;
import io.restassured.http.ContentType;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;

import java.util.Collections;

import static de.bdr.pidp.issuer.issuance.RequestUtil.ATTESTATION_PROOF_TYPE;
import static de.bdr.pidp.issuer.issuance.RequestUtil.JWT_PROOF_TYPE;
import static io.restassured.RestAssured.config;
import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;
import static org.mockito.Mockito.mock;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class CredentialConfigurationMetricTest {

    @LocalServerPort
    private int port;

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private MeterRegistry meterRegistry;

    @Autowired
    private RequestEncryptionJWKSupplier requestEncryptionJWKSupplier;

    static class MetricTestConfig {
        @Bean
        @Primary
        public CredentialService credentialService() {
            return mock(CredentialService.class);
        }
    }

    @DisplayName("Count credential.configuration.usage on credential request")
    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void test001(CredentialConfigurationID id) {
        int initialCount = (int) meterRegistry.counter("credential.configuration.usage", "id", id.getName()).count();

        var body = RequestUtil.getCredentialRequestBody(id.getName(), JWT_PROOF_TYPE, Collections.emptyList());

        given()
            .when()
            .header("Authorization", RequestUtil.AUTHORIZATION_VALUE)
            .body(body)
            .contentType(ContentType.JSON)
            .port(port)
            .post("/credential");

        var expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("credential.configuration.usage", Tag.of("id", id.getName()))
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("credential_configuration_usage_total{id=\"" + id.getName() + "\"} " + expectedCount + ".0"));
    }

    @DisplayName("Count credential.configuration.usage on encrypted credential request")
    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void test002(CredentialConfigurationID id) {
        int initialCount = (int) meterRegistry.counter("credential.configuration.usage", "id", id.getName()).count();

        var body = RequestUtil.getCredentialRequestBody(id.getName(), ATTESTATION_PROOF_TYPE, Collections.emptyList());

        var jwk = requestEncryptionJWKSupplier.jwks().getKeys().getFirst();
        var encBody = TestUtils.generateEncryptedJWT(jwk.toECKey(), body).serialize();

        given()
            .config(config().encoderConfig(encoderConfig().encodeContentTypeAs("application/jwt", ContentType.TEXT)))
            .when()
            .header("Authorization", RequestUtil.AUTHORIZATION_VALUE)
            .body(encBody)
            .contentType("application/jwt")
            .port(port)
            .post("/credential");

        var expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("credential.configuration.usage", Tag.of("id", id.getName()))
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("credential_configuration_usage_total{id=\"" + id.getName() + "\"} " + expectedCount + ".0"));
    }

    @DisplayName("Count credential.configuration.usage on encrypted credential request with response encryption")
    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void test003(CredentialConfigurationID id) {
        int initialCount = (int) meterRegistry.counter("credential.configuration.usage", "id", id.getName()).count();

        var resJwk = TestUtils.generateECDHEncryptionKey();
        var resEnc = EncryptionMethod.A256GCM;
        var body = RequestUtil.getCredentialRequestBody(id.getName(), ATTESTATION_PROOF_TYPE, Collections.emptyList(), resJwk, resEnc);

        var reqJwk = requestEncryptionJWKSupplier.jwks().getKeys().getFirst();
        var encBody = TestUtils.generateEncryptedJWT(reqJwk.toECKey(), body).serialize();

        given()
            .config(config().encoderConfig(encoderConfig().encodeContentTypeAs("application/jwt", ContentType.TEXT)))
            .when()
            .header("Authorization", RequestUtil.AUTHORIZATION_VALUE)
            .body(encBody)
            .contentType("application/jwt")
            .port(port)
            .post("/credential");

        var expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("credential.configuration.usage", Tag.of("id", id.getName()))
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("credential_configuration_usage_total{id=\"" + id.getName() + "\"} " + expectedCount + ".0"));
    }

    @DisplayName("Count credential.configuration.unknown on unknown credential request")
    @Test
    void test004() {
        int initialCount = (int) meterRegistry.counter("credential.configuration.unknown").count();

        var body = RequestUtil.getCredentialRequestBody("unknown", JWT_PROOF_TYPE, Collections.emptyList());

        given()
            .when()
            .header("Authorization", RequestUtil.AUTHORIZATION_VALUE)
            .body(body)
            .contentType(ContentType.JSON)
            .port(port)
            .post("/credential");

        var expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("credential.configuration.unknown")
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("credential_configuration_unknown_total " + expectedCount + ".0"));
    }
}
