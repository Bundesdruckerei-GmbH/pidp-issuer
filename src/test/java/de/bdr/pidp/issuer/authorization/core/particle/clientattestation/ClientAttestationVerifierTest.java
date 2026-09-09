/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.authorization.ConfigTestData;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.service.AuthChallengeService;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ClientAttestationVerifierTest {

    private final String clientId = ClientIds.validClientIdForSelfSigned().toString();
    private final Set<X509Certificate> rootCerts = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED;
    private final AuthChallengeService authChallengeMock = mock(AuthChallengeService.class);
    private final ClientAttestationVerifier verifier = new ClientAttestationVerifier(
        JWSAlgorithm.Family.SIGNATURE,
        JWSAlgorithm.Family.SIGNATURE,
        ConfigTestData.AUTH_CONFIG.getCredentialIssuerIdentifier(),
        ConfigTestData.AUTH_CONFIG.allowSelfSignedAttestationCert(),
        ConfigTestData.AUTH_CONFIG.getProofTimeTolerance(),
        true,
        authChallengeMock
    );
    private final String validChallenge = "valid";

    @BeforeEach
    void setUp() {
        Mockito.lenient().doReturn(true).when(authChallengeMock).consume(validChallenge);
    }

    @Test
    void success() {
        var jwt = TestUtils.getValidClientAttestationJwt();
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        var values = verifier.verify(jwt, pop, rootCerts, clientId);

        assertThat(values.confirmationKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(values.statusListRef()).isEqualTo(TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF);
        verify(authChallengeMock).consume(validChallenge);
    }

    @Test
    void successWithChallengeNotSupported() {
        var verifierNoChallenge = new ClientAttestationVerifier(
            JWSAlgorithm.Family.SIGNATURE,
            JWSAlgorithm.Family.SIGNATURE,
            ConfigTestData.AUTH_CONFIG.getCredentialIssuerIdentifier(),
            ConfigTestData.AUTH_CONFIG.allowSelfSignedAttestationCert(),
            ConfigTestData.AUTH_CONFIG.getProofTimeTolerance(),
            false,
            authChallengeMock
        );
        var jwt = TestUtils.getValidClientAttestationJwt();
        var pop = TestUtils.getValidClientAttestationPopJwt();

        var values = verifierNoChallenge.verify(jwt, pop, rootCerts, clientId);

        assertThat(values.confirmationKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(values.statusListRef()).isEqualTo(TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF);
        verify(authChallengeMock, never()).consume(anyString());
    }

    @Test
    void successWithSubSignedClientAttestation() {
        var jwt = TestUtils.getValidClientAttestationJwtSubSigned();
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        var values = verifier.verify(jwt, pop, TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_CHAIN_CA, ClientIds.validClientIdForSelfSigned().toString());

        assertThat(values.confirmationKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(values.statusListRef()).isEqualTo(TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF);
    }

    @Test
    void successWithoutStatusListRef() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults().claim("status", null).build();
        var jwt = TestUtils.getClientAttestationJwt(claims, TestUtils.CLIENT_ATTESTATION_TYPE);
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        var values = verifier.verify(jwt, pop, rootCerts, clientId);

        assertThat(values.confirmationKey()).isEqualTo(TestUtils.DEVICE_PUBLIC_KEY);
        assertThat(values.statusListRef()).isNull();
    }

    @Test
    void invalidClientAttestationJOSEObjectType() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults().build();
        var jwt = TestUtils.getClientAttestationJwt(claims, JOSEObjectType.JWT);
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation is invalid: JOSE header typ (type) JWT not allowed");
    }

    @Test
    void invalidClientAttestationPoPJOSEObjectType() {
        var jwt = TestUtils.getValidClientAttestationJwt();
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge).build();
        var pop = TestUtils.getClientAttestationPoPJwt(claims, JOSEObjectType.JWT);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation PoP is invalid: JOSE header typ (type) JWT not allowed");
    }

    @Test
    void invalidClientAttestationSignature() {
        var jwt = TestUtils.getInvalidClientAttestationJwt();
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessageStartingWith("Client Attestation is invalid");
    }

    @Test
    void missingClientAttestationX5CHeader() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults().build();
        var jwt = TestUtils.buildJWT(claims, TestUtils.CLIENT_ATTESTATION_TYPE, (ECPrivateKey) TestUtils.CLIENT_PRIVATE_KEY, TestUtils.CLIENT_PUBLIC_KEY);
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation is invalid: Missing JOSE X.509 certificate chain (x5c) header");
    }

    @Test
    void invalidClientInstanceKey() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults();
        claims.claim("cnf", Map.of("jwk", TestUtils.generateEcKey().toPublicJWK().toJSONObject()));
        var jwt = TestUtils.getClientAttestationJwt(claims.build(), TestUtils.CLIENT_ATTESTATION_TYPE);
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation PoP is invalid: Signed JWT rejected: Invalid signature");
    }

    @Test
    void invalidClientAttestationClaim() {
        var claims = TestUtils.getClientAttestationClaimsBuilderWithDefaults();
        claims.subject("invalid");
        var jwt = TestUtils.getClientAttestationJwt(claims.build(), TestUtils.CLIENT_ATTESTATION_TYPE);
        var pop = TestUtils.getValidClientAttestationPopJwt(validChallenge);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation is invalid: JWT subject does not match client_id");
    }

    @Test
    void invalidClientAttestationPoPClaim() {
        var jwt = TestUtils.getValidClientAttestationJwt();
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge);
        claims.issuer("invalid");
        var pop = TestUtils.getClientAttestationPoPJwt(claims.build(), TestUtils.CLIENT_ATTESTATION_POP_TYPE);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation PoP is invalid: JWT issuer does not match client_id");
    }

    @Test
    void invalidClientAttestationPoPChallenge() {
        var jwt = TestUtils.getValidClientAttestationJwt();
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults("invalid");
        var pop = TestUtils.getClientAttestationPoPJwt(claims.build(), TestUtils.CLIENT_ATTESTATION_POP_TYPE);

        assertThatThrownBy(() -> verifier.verify(jwt, pop, rootCerts, clientId))
            .isInstanceOf(InvalidClientException.class)
            .hasMessage("Client Attestation PoP is invalid: Unknown or expired JWT challenge");
    }
}
