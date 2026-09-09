/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialResponseEncryptionResult;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialResult;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.List;

@NullMarked
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class IssuanceResponseFactory {

    private static final JsonMapper MAPPER = new JsonMapper();
    private static final MediaType APPLICATION_JWT = new MediaType("application", "jwt");
    private static final String CREDENTIALS = "credentials";
    private static final String CREDENTIAL = "credential";

    public static ResponseEntity<JsonNode> createCredentialResponse(CredentialResult credentialResult) {
        ObjectNode jsonBody = buildJsonBody(credentialResult.serializedCredentials());

        return ResponseEntity
            .status(HttpStatus.OK)
            .body(jsonBody);
    }

    public static ResponseEntity<String> createEncryptedCredentialResponse(CredentialResponseEncryptionResult credentialResult) {
        var jsonPayload = buildJsonBody(credentialResult.serializedCredentials());
        var stringPayload = jsonPayload.toString();
        var encryptedBody = generateEncryptedJWT(credentialResult.resEncKAKey(), credentialResult.resEncAlgorithm(), credentialResult.encMethod(), stringPayload);

        return ResponseEntity
            .status(HttpStatus.OK)
            .contentType(APPLICATION_JWT)
            .body(encryptedBody.serialize());
    }

    private static ObjectNode buildJsonBody(List<String> credentials) {
        var jsonBody = MAPPER.createObjectNode();
        var jsonCredentials = jsonBody.putArray(CREDENTIALS);
        credentials.forEach(credential -> jsonCredentials.add(MAPPER.createObjectNode().put(CREDENTIAL, credential)));

        return jsonBody;
    }

    public static JWEObject generateEncryptedJWT(JWK encryptionKAKey, JWEAlgorithm alg, EncryptionMethod encMethod, String payload) {
        var header = new JWEHeader.Builder(alg, encMethod)
            .keyID(encryptionKAKey.getKeyID())
            .build();
        var payloadObj = new Payload(payload);
        var jwe = new JWEObject(header, payloadObj);
        try {
            JWEEncrypter encrypter = switch (encryptionKAKey) {
                case ECKey ecKey -> new ECDHEncrypter(ecKey);
                default -> throw new PidServerException("No encrypter for provided credential response encryption key available");
            };
            jwe.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new PidServerException("Encrypting credential response failed", e);
        }
        return jwe;
    }
}
