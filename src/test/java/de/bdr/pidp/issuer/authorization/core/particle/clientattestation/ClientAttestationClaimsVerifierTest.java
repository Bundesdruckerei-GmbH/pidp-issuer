/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jwt.proc.BadJWTException;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientAttestationClaimsVerifierTest {

    private final int maxClockSkew = 30;
    private final String clientId = ClientIds.validClientIdForSelfSigned().toString();
    private final ClientAttestationClaimsVerifier verifier = new ClientAttestationClaimsVerifier(maxClockSkew);

    private ClientAttestationSecurityContext context;

    @BeforeEach
    void setUp() {
        context = new ClientAttestationSecurityContext(
            TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED,
            clientId,
            null
        );
    }

    @Test
    void success() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults().build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(context.getStatusListRef()).isEqualTo(TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF);
    }

    @Test
    void missingIssueTime() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .issueTime(null)
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
    }

    @Test
    void aheadIssueTime() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issue time ahead of current time");
    }

    @Test
    void aheadIssueTimeWithinTolerance() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
    }

    @Test
    void missingExpirationTime() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .expirationTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT expiration (exp) claim");
    }

    @Test
    void pastExpirationTime() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Expired JWT");
    }

    @Test
    void pastExpirationTimeWithinTolerance() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .issueTime(Date.from(Instant.now().minusSeconds(maxClockSkew / 2)))
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
    }

    @Test
    void missingNotBeforeTime() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .notBeforeTime(null)
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
    }

    @Test
    void beforeNotBeforeTime() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .notBeforeTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT before use time");
    }

    @Test
    void beforeNotBeforeTimeWithinTolerance() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .notBeforeTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid"})
    @NullAndEmptySource
    void invalidOrMissingIssuer(String issuer) {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .issuer(issuer)
            .build();


        assertThatCode(() -> verifier.verify(claims, context)).doesNotThrowAnyException();
    }

    @Test
    void missingSubject() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .subject(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void emptySubject() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .subject("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT subject does not match client_id");
    }

    @Test
    void invalidSubject() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .subject("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT subject does not match client_id");
    }

    @Test
    void missingConfirmation() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("cnf", null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT confirmation key (cnf.jwk) claim");
    }

    @Test
    void invalidConfirmationType() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("cnf", "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT confirmation key (cnf.jwk) claim");
    }

    @Test
    void missingConfirmationKey() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("cnf", Map.of("wrong key", "some value"))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT confirmation key (cnf.jwk) claim");
    }

    @Test
    void invalidConfirmationKeyType() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("cnf", Map.of("jwk", "invalid"))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT confirmation key: Unexpected type of JSON object member with key jwk");
    }

    @Test
    void invalidConfirmationKey() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("cnf", Map.of("jwk", Map.of("not a", "jwk")))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT confirmation key: Missing key type \"kty\" parameter");
    }

    @Test
    void missingStatus() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", null)
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(context.getStatusListRef()).isNull();
    }

    @Test
    void emptyStatus() throws BadJWTException {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", Collections.emptyMap())
            .build();

        verifier.verify(claims, context);

        assertThat(context.getKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(context.getStatusListRef()).isNull();
    }

    @Test
    void emptyStatusList() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", Map.of("status_list", Collections.emptyMap()))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid status list reference: could not be parsed");
    }

    @Test
    void missingStatusListURI() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", Map.of("status_list", Map.of("idx", 10)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid status list reference: could not be parsed");
    }

    @Test
    void missingStatusListIndex() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", Map.of("status_list", Map.of("uri", "http://bdr.de/pidp/dummy-status-list")))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid status list reference: could not be parsed");
    }

    @Test
    void invalidStatusListURI() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", Map.of("status_list", Map.of("uri", "no valid URI", "idx", 10)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid status list reference: could not be parsed");
    }

    @Test
    void invalidStatusListIndexType() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults()
            .claim("status", Map.of("status_list", Map.of("uri", "http://bdr.de/pidp/dummy-status-list", "idx", "10")))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid status list reference: could not be parsed");
    }
}
