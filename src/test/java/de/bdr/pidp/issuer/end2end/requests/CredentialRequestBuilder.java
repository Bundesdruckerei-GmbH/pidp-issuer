/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.SupportedProofTypes;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestConfig;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.springframework.http.HttpMethod;
import tools.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static de.bdr.pidp.issuer.testdata.TestUtils.DPOP_SCHEME;

public class CredentialRequestBuilder extends RequestBuilder<CredentialRequestBuilder> {

    public static CredentialRequestBuilder validSdJwt(String dpopNonce, String accessToken) {
        return valid(dpopNonce, accessToken, CredentialConfigurationID.SD_JWT_V1);
    }

    public static CredentialRequestBuilder validSdJwtV2(String dpopNonce, String accessToken) {
        return valid(dpopNonce, accessToken, CredentialConfigurationID.SD_JWT_V2);
    }

    public static CredentialRequestBuilder validSdJwtV3(String dpopNonce, String accessToken) {
        return valid(dpopNonce, accessToken, CredentialConfigurationID.SD_JWT_V3_BETA);
    }

    public static CredentialRequestBuilder validMdoc(String dpopNonce, String accessToken) {
        return valid(dpopNonce, accessToken, CredentialConfigurationID.MSO_MDOC_V1);
    }

    public static CredentialRequestBuilder validMdocV2(String dpopNonce, String accessToken) {
        return valid(dpopNonce, accessToken, CredentialConfigurationID.MSO_MDOC_V2);
    }

    public static CredentialRequestBuilder validMdocV3(String dpopNonce, String accessToken) {
        return valid(dpopNonce, accessToken, CredentialConfigurationID.MSO_MDOC_V3_BETA);
    }

    private static CredentialRequestBuilder valid(String dpopNonce, String accessToken, CredentialConfigurationID id) {
        return new CredentialRequestBuilder()
            .withCredentialConfigurationId(id)
            .withContentType("application/json; charset=utf-8")
            .withDPoPHeader(accessToken, dpopNonce)
            .withAccessToken(accessToken);
    }

    public CredentialRequestBuilder() {
        super(HttpMethod.POST);
        withUrl(getCredentialPath());
    }

    public static String getCredentialPath() {
        return "/credential";
    }

    public static URI getCredentialUri() {
        return URI.create(TestConfig.pidiBaseUrl() + getCredentialPath());
    }

    public static String getAudience() {
        return TestConfig.pidiBaseUrl();
    }

    public CredentialRequestBuilder withCredentialConfigurationId(CredentialConfigurationID credentialConfigurationId) {
        withJsonBodyProperty("credential_configuration_id", credentialConfigurationId.getName());
        return this;
    }

    public CredentialRequestBuilder withKeyAttestationProofs(String jwtNonce, int nrKeys) {
        var jwt = TestUtils.getValidKeyAttestationJwt(jwtNonce, nrKeys);
        var body = buildAttestationProofsBody(jwt);
        withJsonBody(body);
        return this;
    }

    public CredentialRequestBuilder withProofs(String jwtNonce, int count) {
        var jwts = IntStream.range(0, count).mapToObj(_ -> TestUtils.buildProofJwt(ClientIds.validClientIdForSelfSigned().toString(), getAudience(), Instant.now(), jwtNonce)).toList();
        var body = buildProofsBody(jwts);
        withJsonBody(body);
        return this;
    }

    public CredentialRequestBuilder withResponseEncryption(JWK jwk) {
        var encNode = objectMapper.createObjectNode();
        encNode.set("jwk", objectMapper.readTree(jwk.toJSONString()));
        encNode.put("enc", EncryptionMethod.A256GCM.getName());

        var body = objectMapper.createObjectNode();
        body.set("credential_response_encryption", encNode);

        withJsonBody(body);
        return this;
    }

    public CredentialRequestBuilder withRequestEncryption(Map<String, Object> jwkMap) {
        ECKey jwk;
        try {
            jwk = ECKey.parse(jwkMap);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        var body = super.requestBody.toString();
        String jwe = TestUtils.generateEncryptedJWT(jwk, body).serialize();
        withContentType("application/jwt");
        withPlainBody(jwe);
        return this;
    }

    public CredentialRequestBuilder withDPoPHeader(String accessToken, String dpopNonce) {
        final SignedJWT dpopProof = TestUtils.getDPoPProof(httpMethod, getCredentialUri(), new DPoPAccessToken(accessToken), Nonce.parse(dpopNonce));
        withHeader("dpop", dpopProof.serialize());
        return this;
    }

    public CredentialRequestBuilder withAccessToken(String token) {
        withHeader("Authorization", "%s %s".formatted(DPOP_SCHEME, token));
        return this;
    }

    private ObjectNode buildProofsBody(List<SignedJWT> jwts) {
        var body = objectMapper.createObjectNode();
        var proofs = body.putObject("proofs");
        var jwtArr = proofs.putArray(SupportedProofTypes.JWT.getValue());
        jwts.stream().map(JWSObject::serialize).forEach(jwtArr::add);
        return body;
    }

    private ObjectNode buildAttestationProofsBody(SignedJWT jwt) {
        var body = objectMapper.createObjectNode();
        var proof = body.putObject("proofs");
        var jwtArr = proof.putArray(SupportedProofTypes.ATTESTATION.getValue());
        jwtArr.add(jwt.serialize());
        return body;
    }
}
