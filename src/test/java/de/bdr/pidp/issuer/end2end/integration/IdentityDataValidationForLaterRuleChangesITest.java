/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.integration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPTokenRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.service.RefreshTokenIssuer;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenLifecyclePortOut;
import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.base.identitydata.StructuredPlace;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import de.bdr.pidp.issuer.identification.core.seedcredential.SeedCredentialService;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.SupportedProofTypes;
import de.bdr.pidp.issuer.issuance.policy.PidIdentityDataValidator;
import de.bdr.pidp.issuer.issuance.policy.ValidIssuanceDecision;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestConfig;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;

import static de.bdr.pidp.issuer.testdata.TestUtils.DPOP_SCHEME;
import static io.restassured.module.webtestclient.RestAssuredWebTestClient.given;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

class IdentityDataValidationForLaterRuleChangesITest extends RestAssuredWebTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String URL_PATH_TOKEN = "/token";
    private static final String URL_PATH_NONCE = "/nonce";
    private static final String URL_PATH_CREDENTIAL = "/credential";
    private static final URI URI_TOKEN = URI.create(TestConfig.pidiBaseUrl() + URL_PATH_TOKEN);
    private static final URI URI_CREDENTIAL = URI.create(TestConfig.pidiBaseUrl() + URL_PATH_CREDENTIAL);
    private static final String CLIENT_ID = ClientIds.validClientIdForSelfSigned().toString();

    @Autowired
    private RefreshTokenIssuer  refreshTokenIssuer;

    @Autowired
    private SeedCredentialService seedCredentialService;

    @Autowired
    private RefreshTokenLifecyclePortOut refreshTokenLifecyclePort;

    private final DPoPTokenRequestVerifier verifier = new DPoPTokenRequestVerifier(Set.copyOf(JWSAlgorithm.Family.EC), URI_TOKEN, 500, 500, null);

    @Test
    @DisplayName("Process RefreshToken with Error when Identity data invalid")
    void errorInvalidRefreshTokenWhenIdentityDataInvalid() throws InvalidDPoPProofException, JOSEException, ParseException {
        var refreshToken = getRefreshTokenWithInvalidIdentityData();
        var serializedRefreshToken = refreshToken.serialize();
        refreshTokenLifecyclePort.registerToken(
            refreshToken.getJWTClaimsSet().getJWTID(),
            refreshToken.getJWTClaimsSet().getSubject(),
            refreshToken.getJWTClaimsSet().getExpirationTime().toInstant(),
            TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF
        );

        var response = given()
            .params(
                "grant_type", GrantType.REFRESH_TOKEN.getValue(),
                "client_id", CLIENT_ID,
                "refresh_token", serializedRefreshToken)
            .headers(
                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8",
                "dpop", getDpopProofForTokenRequest(null).serialize(),
                "OAuth-Client-Attestation", TestUtils.getValidClientAttestationJwt().serialize(),
                "OAuth-Client-Attestation-PoP", TestUtils.getValidClientAttestationPopJwt().serialize())
            .when()
            .post(URL_PATH_TOKEN)
            .then()
            .assertThat()
            .status(HttpStatus.BAD_REQUEST)
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())

            .body("token_type", is(nullValue()))
            .body("access_token", is(nullValue()))
            .body("error", is("use_dpop_nonce"))
            .header("DPoP-Nonce", is(notNullValue()));

        String newDpopNonce = response.extract().header("DPoP-Nonce");

        given()
            .params(
                "grant_type", GrantType.REFRESH_TOKEN.getValue(),
                "client_id", CLIENT_ID,
                "refresh_token", serializedRefreshToken)
            .headers(
                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8",
                "dpop", getDpopProofForTokenRequest(newDpopNonce).serialize(),
                "OAuth-Client-Attestation", TestUtils.getValidClientAttestationJwt().serialize(),
                "OAuth-Client-Attestation-PoP", TestUtils.getValidClientAttestationPopJwt().serialize())
            .when()
            .post(URL_PATH_TOKEN)
            .then()
            .assertThat()
            .status(HttpStatus.BAD_REQUEST)
            .body("error", is("invalid_grant"))
            .body("error_description", is("Seed credential at the refresh token is invalid"));
    }

    @Test
    @DisplayName("Process Credential request with Error when Identity data invalid")
    void errorInvalidCredentialRequestWhenIdentityDataInvalid() throws InvalidDPoPProofException, JOSEException, ParseException {
        var refreshToken = getRefreshTokenWithInvalidIdentityData();
        var serializedRefreshToken = refreshToken.serialize();
        refreshTokenLifecyclePort.registerToken(
            refreshToken.getJWTClaimsSet().getJWTID(),
            refreshToken.getJWTClaimsSet().getSubject(),
            refreshToken.getJWTClaimsSet().getExpirationTime().toInstant(),
            TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF
        );

        var response = given()
            .params(
                "grant_type", GrantType.REFRESH_TOKEN.getValue(),
                "client_id", CLIENT_ID,
                "refresh_token", serializedRefreshToken)
            .headers(
                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8",
                "dpop", getDpopProofForTokenRequest(null).serialize(),
                "OAuth-Client-Attestation", TestUtils.getValidClientAttestationJwt().serialize(),
                "OAuth-Client-Attestation-PoP", TestUtils.getValidClientAttestationPopJwt().serialize())
            .when()
            .post(URL_PATH_TOKEN)
            .then()
            .assertThat()
            .status(HttpStatus.BAD_REQUEST)
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())

            .body("token_type", is(nullValue()))
            .body("access_token", is(nullValue()))
            .body("error", is("use_dpop_nonce"))
            .header("DPoP-Nonce", is(notNullValue()));

        String newDpopNonce = response.extract().header("DPoP-Nonce");
        String dpopNonceForCredentialRequest;
        String accessToken;

        try (MockedStatic<PidIdentityDataValidator> pidIdentityDataValidatorMock = mockStatic(PidIdentityDataValidator.class)) {

            pidIdentityDataValidatorMock.when(() -> PidIdentityDataValidator.validatePidIdentityData(any()))
                .thenReturn(new ValidIssuanceDecision());

            var secondResponse = given()
                .params(
                    "grant_type", GrantType.REFRESH_TOKEN.getValue(),
                    "client_id", CLIENT_ID,
                    "refresh_token", serializedRefreshToken)
                .headers(
                    "Content-Type", "application/x-www-form-urlencoded; charset=utf-8",
                    "dpop", getDpopProofForTokenRequest(newDpopNonce).serialize(),
                    "OAuth-Client-Attestation", TestUtils.getValidClientAttestationJwt().serialize(),
                    "OAuth-Client-Attestation-PoP", TestUtils.getValidClientAttestationPopJwt().serialize())
                .when()
                .post(URL_PATH_TOKEN)
                .then()
                .assertThat()
                .status(HttpStatus.OK);
            dpopNonceForCredentialRequest = secondResponse.extract().header("DPoP-Nonce");
            accessToken = secondResponse.extract().body().jsonPath().getString("access_token");
        }

        String cNonce = given()
            .when()
            .post(URL_PATH_NONCE)
            .then()
            .assertThat()
            .status(HttpStatus.OK)
            .extract().body().jsonPath().getString("c_nonce");

        var requestBody = OBJECT_MAPPER.createObjectNode();
        requestBody.put("credential_configuration_id", CredentialConfigurationID.SD_JWT_V2.getName());
        var proofs = requestBody.putObject("proofs");
        var jwt = TestUtils.buildProofJwt(CLIENT_ID, TestUtils.ISSUER_IDENTIFIER_AUDIENCE, Instant.now(), cNonce);
        ArrayNode jwtArr = proofs.putArray(SupportedProofTypes.JWT.getValue());
        jwtArr.add(jwt.serialize());

        given()
            .body(requestBody)
            .headers(
                "Content-Type", "application/json; charset=utf-8",
                "dpop", getDpopProofForCredentialRequest(dpopNonceForCredentialRequest, accessToken).serialize(),
                "Authorization", "%s %s".formatted(DPOP_SCHEME, accessToken))
            .when()
            .post(URL_PATH_CREDENTIAL)
            .then()
            .assertThat()
            .status(HttpStatus.BAD_REQUEST)
            .body("error", is("credential_request_denied"))
            .body("error_description", is("Identity data validation failed."));
    }

    private static SignedJWT getDpopProofForTokenRequest(String nonce) {
        return TestUtils.getDPoPProof(HttpMethod.POST, URI_TOKEN, Nonce.parse(nonce));
    }

    private static SignedJWT getDpopProofForCredentialRequest(String nonce, String accessToken) {
        return TestUtils.getDPoPProof(HttpMethod.POST, URI_CREDENTIAL, new DPoPAccessToken(accessToken), Nonce.parse(nonce));
    }

    private SignedJWT getRefreshTokenWithInvalidIdentityData() throws InvalidDPoPProofException, JOSEException {
        Nonce nonce = Nonce.parse(null);
        // invalid nationality, nationality must not be null at documentTypes AR, AS, AF and IC; can only be null with documentType ID
        IdentityData invalidIdentityData = new IdentityData(DocumentType.AR.name(), null,
            "2046-01-23", "ERIKA", "MUSTERMANN", null, null,
            new DateOfBirth(null, "19640812"),
            new Place(null, "BERLIN", null), null, "GABLER",
            new Place(new StructuredPlace("HEIDESTRASSE 17", "KÖLN", "D", null, "51147"), null, null),
            new RestrictedId("RVJJS0E="));

        JWKThumbprintConfirmation cnf = verifier.verify(new DPoPIssuer("client_id dummy"), getDpopProofForTokenRequest(null), nonce);
        SeedCredentialData data = seedCredentialService.createSeedCredential(invalidIdentityData);
        SeedCredential seedCredential = new SeedCredential(data.seedCredential(), data.jti(), data.sub(), Instant.now().plusSeconds(500));
        return refreshTokenIssuer.buildRefreshToken(CLIENT_ID, "pid", new Base64URL(cnf.getValue().toString()), seedCredential);
    }
}
