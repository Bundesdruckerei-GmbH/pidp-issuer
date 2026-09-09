/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.restdoc;

import de.bdr.pidp.issuer.end2end.requests.CredentialRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.Documentation;
import de.bdr.pidp.issuer.end2end.requests.HealthRequestBuilder;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;

class ExampleTests extends RestDocTest {

    @Test
    @DisplayName("Credential request happy path with SdJwt")
    void test006() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt/nonce"));
        CredentialRequestBuilder
            .validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request enc happy path with SdJwt")
    void test024() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt-enc/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-enc/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-enc/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-enc/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-enc/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-enc/nonce"));
        var metadataResponse = steps.doCredentialIssuerMetadataRequest(new Documentation("sdjwt-enc/issuer-metadata"));
        CredentialRequestBuilder
            .validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withRequestEncryption(metadataResponse.requestEncryptionJWK())
            .withDocumentation(new Documentation("sdjwt-enc/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request response enc happy path with SdJwt")
    void test025() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt-full-enc/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-full-enc/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-full-enc/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-full-enc/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-full-enc/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-full-enc/nonce"));
        var metadataResponse = steps.doCredentialIssuerMetadataRequest(new Documentation("sdjwt-full-enc/issuer-metadata"));
        var jwk = TestUtils.generateECDHEncryptionKey();
        CredentialRequestBuilder
            .validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withResponseEncryption(jwk.toPublicJWK())
            .withRequestEncryption(metadataResponse.requestEncryptionJWK())
            .withDocumentation(new Documentation("sdjwt-full-enc/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .header(HttpHeaders.CONTENT_TYPE, is("application/jwt"));
    }

    @Test
    @DisplayName("Credential request happy path with SdJwt v2")
    void test006_2() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt2/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt2/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt2/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt2/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt2/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt2/nonce"));
        CredentialRequestBuilder
            .validSdJwtV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt2/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with SdJwt v3")
    void test006_3() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt3/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt3/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt3/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt3/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt3/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt3/nonce"));
        CredentialRequestBuilder
            .validSdJwtV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt3/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with mdoc")
    void test007() {
        var clResponse = steps.doChallenge(new Documentation("mdoc/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc/nonce"));
        CredentialRequestBuilder
            .validMdoc(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with mdoc v2")
    void test007_2() {
        var clResponse = steps.doChallenge(new Documentation("mdoc2/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc2/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc2/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc2/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc2/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc2/nonce"));
        CredentialRequestBuilder
            .validMdocV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc2/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with mdoc v3")
    void test007_3() {
        var clResponse = steps.doChallenge(new Documentation("mdoc3/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc3/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc3/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc3/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc3/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc3/nonce"));
        CredentialRequestBuilder
            .validMdocV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc3/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential batch request happy path with SdJwt")
    void test008() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt-batch/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-batch/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-batch/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-batch/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-batch/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-batch/nonce"));
        CredentialRequestBuilder
            .validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 2)
            .withDocumentation(new Documentation("sdjwt-batch/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(2));
    }

    @Test
    @DisplayName("Credential batch request happy path with SdJwt v2")
    void test008_2() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt2-batch/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt2-batch/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt2-batch/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt2-batch/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt2-batch/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt2-batch/nonce"));
        CredentialRequestBuilder
            .validSdJwtV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 2)
            .withDocumentation(new Documentation("sdjwt2-batch/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(2));
    }

    @Test
    @DisplayName("Credential batch request happy path with SdJwt v3")
    void test008_3() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt3-batch/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt3-batch/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt3-batch/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt3-batch/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt3-batch/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt3-batch/nonce"));
        CredentialRequestBuilder
            .validSdJwtV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 2)
            .withDocumentation(new Documentation("sdjwt3-batch/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(2));
    }

    @Test
    @DisplayName("Credential batch request happy path with mdoc")
    void test009() {
        var clResponse = steps.doChallenge(new Documentation("mdoc-batch/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc-batch/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc-batch/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc-batch/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc-batch/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc-batch/nonce"));
        CredentialRequestBuilder
            .validMdoc(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 2)
            .withDocumentation(new Documentation("mdoc-batch/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(2));
    }

    @Test
    @DisplayName("Credential batch request happy path with mdoc v2")
    void test009_2() {
        var clResponse = steps.doChallenge(new Documentation("mdoc2-batch/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc2-batch/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc2-batch/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc2-batch/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc2-batch/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc2-batch/nonce"));
        CredentialRequestBuilder
            .validMdocV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 2)
            .withDocumentation(new Documentation("mdoc2-batch/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(2));
    }

    @Test
    @DisplayName("Credential batch request happy path with mdoc v3")
    void test009_3() {
        var clResponse = steps.doChallenge(new Documentation("mdoc3-batch/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc3-batch/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc3-batch/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc3-batch/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc3-batch/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc3-batch/nonce"));
        CredentialRequestBuilder
            .validMdocV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 2)
            .withDocumentation(new Documentation("mdoc3-batch/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(2));
    }

    @Test
    @DisplayName("Credential request via refresh token happy path with sdjwt")
    void test014() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt-refresh/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-refresh/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-refresh/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-refresh/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-refresh/token"));
        var cl2Response = steps.doChallenge(new Documentation("sdjwt-refresh/challenge2"));
        var refreshInitResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken(), cl2Response.attestationChallenge(), new Documentation("sdjwt-refresh/token-refresh-init"));
        var refreshResponse = steps.doRefreshTokenRequest(tokenResponse.refreshToken(), refreshInitResponse.dpopNonce(), refreshInitResponse.attestationChallenge(), new Documentation("sdjwt-refresh/token-refresh"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-refresh/nonce"));
        CredentialRequestBuilder
            .validSdJwt(refreshResponse.dpopNonce(), refreshResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt-refresh/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request via refresh token happy path with mdoc")
    void test015() {
        var clResponse = steps.doChallenge(new Documentation("mdoc-refresh/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc-refresh/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc-refresh/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc-refresh/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc-refresh/token"));
        var cl2Response = steps.doChallenge(new Documentation("mdoc-refresh/challenge2"));
        var refreshInitResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken(), cl2Response.attestationChallenge(), new Documentation("mdoc-refresh/token-refresh-init"));
        var refreshResponse = steps.doRefreshTokenRequest(tokenResponse.refreshToken(), refreshInitResponse.dpopNonce(), refreshInitResponse.attestationChallenge(), new Documentation("mdoc-refresh/token-refresh"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc-refresh/nonce"));
        CredentialRequestBuilder
            .validMdoc(refreshResponse.dpopNonce(), refreshResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc-refresh/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with SdJwt and key attestation")
    void test017() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with SdJwt v2 and key attestation")
    void test017_2() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt2-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt2-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt2-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt2-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt2-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt2-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwtV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt2-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with SdJwt v3 and key attestation")
    void test017_3() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt3-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt3-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt3-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt3-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt3-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt3-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwtV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt3-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential batch request happy path with SdJwt and key attestation")
    void test018() {
        int nrKeys = 10;
        var clResponse = steps.doChallenge(new Documentation("sdjwt-batch-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-batch-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-batch-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-batch-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-batch-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-batch-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), nrKeys)
            .withDocumentation(new Documentation("sdjwt-batch-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()))
            .body("credentials", hasSize(nrKeys));
    }

    @Test
    @DisplayName("Credential batch request happy path with SdJwt v2 and key attestation")
    void test018_2() {
        int nrKeys = 10;
        var clResponse = steps.doChallenge(new Documentation("sdjwt2-batch-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt2-batch-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt2-batch-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt2-batch-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt2-batch-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt2-batch-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwtV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), nrKeys)
            .withDocumentation(new Documentation("sdjwt2-batch-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()))
            .body("credentials", hasSize(nrKeys));
    }

    @Test
    @DisplayName("Credential batch request happy path with SdJwt v3 and key attestation")
    void test018_3() {
        int nrKeys = 10;
        var clResponse = steps.doChallenge(new Documentation("sdjwt3-batch-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt3-batch-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt3-batch-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt3-batch-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt3-batch-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt3-batch-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwtV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), nrKeys)
            .withDocumentation(new Documentation("sdjwt3-batch-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()))
            .body("credentials", hasSize(nrKeys));
    }

    @Test
    @DisplayName("Credential request via refresh token happy path with sdjwt and key attestation")
    void test019() {
        var clResponse = steps.doChallenge(new Documentation("sdjwt-refresh-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("sdjwt-refresh-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("sdjwt-refresh-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("sdjwt-refresh-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("sdjwt-refresh-key-attestation/token"));
        var cl2Response = steps.doChallenge(new Documentation("sdjwt-refresh-key-attestation/challenge2"));
        var refreshInitResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken(), cl2Response.attestationChallenge(), new Documentation("sdjwt-refresh-key-attestation/token-refresh-init"));
        var refreshResponse = steps.doRefreshTokenRequest(tokenResponse.refreshToken(), refreshInitResponse.dpopNonce(), refreshInitResponse.attestationChallenge(), new Documentation("sdjwt-refresh-key-attestation/token-refresh"));
        var nonceResponse = steps.doNonceRequest(new Documentation("sdjwt-refresh-key-attestation/nonce"));
        CredentialRequestBuilder
            .validSdJwt(refreshResponse.dpopNonce(), refreshResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("sdjwt-refresh-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with mdoc and key attestation")
    void test020() {
        var clResponse = steps.doChallenge(new Documentation("mdoc-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdoc(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with mdoc v2 and key attestation")
    void test020_2() {
        var clResponse = steps.doChallenge(new Documentation("mdoc2-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc2-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc2-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc2-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc2-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc2-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdocV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc2-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential request happy path with mdoc v3 and key attestation")
    void test020_3() {
        var clResponse = steps.doChallenge(new Documentation("mdoc3-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc3-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc3-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc3-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc3-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc3-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdocV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc3-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Credential batch request happy path with mdoc and key attestation")
    void test021() {
        int nrKeys = 10;
        var clResponse = steps.doChallenge(new Documentation("mdoc-batch-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc-batch-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc-batch-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc-batch-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc-batch-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc-batch-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdoc(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), nrKeys)
            .withDocumentation(new Documentation("mdoc-batch-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(nrKeys));
    }

    @Test
    @DisplayName("Credential batch request happy path with mdoc v2 and key attestation")
    void test021_2() {
        int nrKeys = 10;
        var clResponse = steps.doChallenge(new Documentation("mdoc2-batch-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc2-batch-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc2-batch-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc2-batch-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc2-batch-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc2-batch-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdocV2(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), nrKeys)
            .withDocumentation(new Documentation("mdoc2-batch-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(nrKeys));
    }

    @Test
    @DisplayName("Credential batch request happy path with mdoc v3 and key attestation")
    void test021_3() {
        int nrKeys = 10;
        var clResponse = steps.doChallenge(new Documentation("mdoc3-batch-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc3-batch-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc3-batch-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc3-batch-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc3-batch-key-attestation/token"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc3-batch-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdocV3(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), nrKeys)
            .withDocumentation(new Documentation("mdoc3-batch-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", hasSize(nrKeys));
    }

    @Test
    @DisplayName("Credential request via refresh token happy path with mdoc and key attestation")
    void test022() {
        var clResponse = steps.doChallenge(new Documentation("mdoc-refresh-key-attestation/challenge"));
        var parResponse = steps.doPAR(clResponse.attestationChallenge(), new Documentation("mdoc-refresh-key-attestation/par"));
        var authResponse = steps.doAuthorize(parResponse.requestUri(), new Documentation("mdoc-refresh-key-attestation/authorize"));
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState(), new Documentation("mdoc-refresh-key-attestation/finish-authorization"));
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce(), new Documentation("mdoc-refresh-key-attestation/token"));
        var cl2Response = steps.doChallenge(new Documentation("mdoc-refresh-key-attestation/challenge2"));
        var refreshInitResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken(), cl2Response.attestationChallenge(), new Documentation("mdoc-refresh-key-attestation/token-refresh-init"));
        var refreshResponse = steps.doRefreshTokenRequest(tokenResponse.refreshToken(), refreshInitResponse.dpopNonce(), refreshInitResponse.attestationChallenge(), new Documentation("mdoc-refresh-key-attestation/token-refresh"));
        var nonceResponse = steps.doNonceRequest(new Documentation("mdoc-refresh-key-attestation/nonce"));
        CredentialRequestBuilder
            .validMdoc(refreshResponse.dpopNonce(), refreshResponse.accessToken())
            .withKeyAttestationProofs(nonceResponse.cNonce(), 1)
            .withDocumentation(new Documentation("mdoc-refresh-key-attestation/credential"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body("credentials", is(notNullValue()));
    }

    @Test
    @DisplayName("Health request")
    void test023() {
        HealthRequestBuilder
            .valid()
            .withDocumentation(new Documentation("health"))
            .doRequest()
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .body(equalTo("UP"));
    }
}
