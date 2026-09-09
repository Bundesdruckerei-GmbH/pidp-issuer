/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialResponseEncryptionResult;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialResult;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.util.List;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceResponseFactoryTest {

    private final JsonMapper jsonMapper = new JsonMapper();

    @Test
    void credentialResponseIsCreatedCorrectly() {
        var credentials = List.of("serialized", "credential");
        var result = new CredentialResult(credentials);

        var response = IssuanceResponseFactory.createCredentialResponse(result);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        var body = Objects.requireNonNull(response.getBody());
        assertThat(body.get("credentials")).hasSize(2);
        assertThat(body.get("credentials").get(0).get("credential").asString()).isEqualTo("serialized");
        assertThat(body.get("credentials").get(1).get("credential").asString()).isEqualTo("credential");
    }

    @Test
    void encryptedCredentialResponseIsCreatedCorrectly() throws ParseException, JOSEException {
        var credentials = List.of("serialized", "credential");
        var reqJwk = TestUtils.generateECDHEncryptionKey();
        var reqAlg = (JWEAlgorithm) reqJwk.getAlgorithm();
        var reqEnc = EncryptionMethod.A256GCM;
        var result = new CredentialResponseEncryptionResult(credentials, reqJwk.toPublicJWK(), reqAlg, reqEnc);

        var response = IssuanceResponseFactory.createEncryptedCredentialResponse(result);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).hasToString("application/jwt");
        var body = Objects.requireNonNull(response.getBody());
        var jwe = JWEObject.parse(body);
        jwe.decrypt(new ECDHDecrypter(reqJwk));
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(reqJwk.getKeyID());
        var payload = jsonMapper.readTree(jwe.getPayload().toString());
        assertThat(payload.get("credentials")).hasSize(2);
        assertThat(payload.get("credentials").get(0).get("credential").asString()).isEqualTo("serialized");
        assertThat(payload.get("credentials").get(1).get("credential").asString()).isEqualTo("credential");
    }
}
