/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.integration;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import static io.restassured.module.webtestclient.RestAssuredWebTestClient.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;

class MetadataControllerITest extends RestAssuredWebTest {
    private static final String BASE_URL_REGEX = "https?://\\w++(?:\\.[\\w\\-]+)*+(?::\\d+)?.*";

    @Test
    @DisplayName("Verify the positive call to authorization metadata endpoint")
    void test001() {
        String[] dpopSigningAlgs = JWSAlgorithm.Family.EC.stream().map(Algorithm::toString).toArray(String[]::new);
        String[] clientAttestationSigningAlgs = JWSAlgorithm.Family.SIGNATURE.stream().map(Algorithm::toString).toArray(String[]::new);
        String[] clientAttestationPoPSigningAlgs = clientAttestationSigningAlgs.clone();

        given()
            .when()
            .get("/.well-known/oauth-authorization-server")
            .then()
            .assertThat()
            .statusCode(is(200))
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())

            .body("issuer", matchesPattern(BASE_URL_REGEX))
            .body("authorization_endpoint", matchesPattern(BASE_URL_REGEX + "/authorize"))
            .body("token_endpoint", matchesPattern(BASE_URL_REGEX + "/token"))
            .body("pushed_authorization_request_endpoint", matchesPattern(BASE_URL_REGEX + "/par"))
            .body("require_pushed_authorization_requests", is(true))
            .body("response_types_supported.size()", is(1))
            .body("response_types_supported[0]", is("code"))
            .body("token_endpoint_auth_methods_supported.size()", is(1))
            .body("token_endpoint_auth_methods_supported[0]", is("attest_jwt_client_auth"))
            .body("code_challenge_methods_supported.size()", is(1))
            .body("code_challenge_methods_supported[0]", is("S256"))
            .body("dpop_signing_alg_values_supported", contains(dpopSigningAlgs))
            .body("client_attestation_signing_alg_values_supported", contains(clientAttestationSigningAlgs))
            .body("client_attestation_pop_signing_alg_values_supported", contains(clientAttestationPoPSigningAlgs));
    }

    @Test
    @DisplayName("Verify the positive call to credential metadata endpoint as json")
    void test003() {
        int nrClaimsInV2Config = 24;
        int nrClaimsInV3BetaConfig = 23;
        int nrParentClaimsInV2Config = 2; // for "address" and "age_equal_or_over", only in pid-sd-jwt_2, not in pid-mso-mdoc_2
        int nrParentClaimsInV3BetaConfig = 2; // for "address" and "age_equal_or_over", only in pid-sd-jwt_3-beta, not in pid-mso-mdoc_3-beta

        given()
            .accept(MediaType.APPLICATION_JSON)
            .when()
            .get("/.well-known/openid-credential-issuer")
            .then()
            .assertThat()
            .contentType("application/json")
            .statusCode(is(200))
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())
            .body("credential_endpoint", matchesPattern(BASE_URL_REGEX + "/credential"))
            .body("nonce_endpoint", matchesPattern(BASE_URL_REGEX + "/nonce"))
            .body("batch_credential_issuance.batch_size", is(42))
            .body("credential_request_encryption.jwks.keys.size()", is(1))
            .body("credential_request_encryption.enc_values_supported", contains(EncryptionMethod.A256GCM.getName()))
            .body("credential_request_encryption.encryption_required", is(false))
            .body("credential_response_encryption.alg_values_supported", contains(JWEAlgorithm.ECDH_ES.getName()))
            .body("credential_response_encryption.enc_values_supported", contains(EncryptionMethod.A256GCM.getName()))
            .body("credential_response_encryption.encryption_required", is(false))
            .body("credential_configurations_supported.size()", is(6))
            .body("credential_configurations_supported.pid-sd-jwt.format", is("dc+sd-jwt"))
            .body("credential_configurations_supported.pid-sd-jwt.vct", is("urn:eudi:pid:de:1"))
            .body("credential_configurations_supported.pid-sd-jwt_2.format", is("dc+sd-jwt"))
            .body("credential_configurations_supported.pid-sd-jwt_2.vct", is("urn:eudi:pid:de:1"))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.format", is("dc+sd-jwt"))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.vct", is("urn:eudi:pid:de:1"))
            .body("credential_configurations_supported.pid-mso-mdoc.format", is("mso_mdoc"))
            .body("credential_configurations_supported.pid-mso-mdoc.doctype", is("eu.europa.ec.eudi.pid.1"))
            .body("credential_configurations_supported.pid-mso-mdoc_2.format", is("mso_mdoc"))
            .body("credential_configurations_supported.pid-mso-mdoc_2.doctype", is("eu.europa.ec.eudi.pid.1"))
            .body("credential_configurations_supported.pid-mso-mdoc_3-beta.format", is("mso_mdoc"))
            .body("credential_configurations_supported.pid-mso-mdoc_3-beta.doctype", is("eu.europa.ec.eudi.pid.1"))
            .body("credential_configurations_supported.pid-sd-jwt.proof_types_supported.attestation.key_attestations_required.key_storage.size()", is(1))
            .body("credential_configurations_supported.pid-sd-jwt.proof_types_supported.attestation.key_attestations_required.key_storage[0]", is("iso_18045_high"))
            .body("credential_configurations_supported.pid-sd-jwt.proof_types_supported.attestation.key_attestations_required.user_authentication.size()", is(1))
            .body("credential_configurations_supported.pid-sd-jwt.proof_types_supported.attestation.key_attestations_required.user_authentication[0]", is("iso_18045_high")).body("credential_configurations_supported.pid-sd-jwt.credential_metadata.display.size()", is(2))
            .body("credential_configurations_supported.pid-sd-jwt.credential_metadata.claims.size()", is(23))
            .body("credential_configurations_supported.pid-sd-jwt_2.proof_types_supported.attestation.key_attestations_required.key_storage.size()", is(1))
            .body("credential_configurations_supported.pid-sd-jwt_2.proof_types_supported.attestation.key_attestations_required.key_storage[0]", is("iso_18045_high"))
            .body("credential_configurations_supported.pid-sd-jwt_2.proof_types_supported.attestation.key_attestations_required.user_authentication.size()", is(1))
            .body("credential_configurations_supported.pid-sd-jwt_2.proof_types_supported.attestation.key_attestations_required.user_authentication[0]", is("iso_18045_high")).body("credential_configurations_supported.pid-sd-jwt.credential_metadata.display.size()", is(2))
            .body("credential_configurations_supported.pid-sd-jwt_2.credential_metadata.claims.size()", is(nrClaimsInV2Config + nrParentClaimsInV2Config))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.proof_types_supported.attestation.key_attestations_required.key_storage.size()", is(1))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.proof_types_supported.attestation.key_attestations_required.key_storage[0]", is("iso_18045_high"))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.proof_types_supported.attestation.key_attestations_required.user_authentication.size()", is(1))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.proof_types_supported.attestation.key_attestations_required.user_authentication[0]", is("iso_18045_high")).body("credential_configurations_supported.pid-sd-jwt.credential_metadata.display.size()", is(2))
            .body("credential_configurations_supported.pid-sd-jwt_3-beta.credential_metadata.claims.size()", is(nrClaimsInV3BetaConfig + nrParentClaimsInV3BetaConfig))
            .body("credential_configurations_supported.pid-mso-mdoc.credential_metadata.display.size()", is(2))
            .body("credential_configurations_supported.pid-mso-mdoc.credential_metadata.claims.size()", is(25))
            .body("credential_configurations_supported.pid-mso-mdoc_2.credential_metadata.display.size()", is(2))
            .body("credential_configurations_supported.pid-mso-mdoc_2.credential_metadata.claims.size()", is(nrClaimsInV2Config))
            .body("credential_configurations_supported.pid-mso-mdoc_3-beta.credential_metadata.display.size()", is(2))
            .body("credential_configurations_supported.pid-mso-mdoc_3-beta.credential_metadata.claims.size()", is(nrClaimsInV3BetaConfig))
        ;
    }

    @Test
    @DisplayName("Verify the positive call to credential metadata endpoint as jwt")
    void test004() {
        given()
            .accept("application/jwt")
            .when()
            .get("/.well-known/openid-credential-issuer")
            .then()
            .assertThat()
            .contentType("application/jwt")
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())
            .statusCode(is(200));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "text/html", "application/pdf"})
    @EmptySource
    @DisplayName("Verify the positive call to credential metadata endpoint always json for all accept headers")
    void test005(String accept) {
        given()
            .accept(accept)
            .when()
            .get("/.well-known/openid-credential-issuer")
            .then()
            .assertThat()
            .contentType("application/json")
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())
            .statusCode(is(200));
    }

    @Test
    @DisplayName("Verify the positive call to jwt metadata endpoint")
    void test006() {
        given()
            .when()
            .get("/.well-known/jwt-vc-issuer")
            .then()
            .assertThat()
            .statusCode(is(200))
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())
            .body("issuer", matchesPattern(BASE_URL_REGEX))
            .body("jwks.keys", hasSize(1))
            .body("jwks.keys[0]", hasKey("kid"))
        ;
    }
}
