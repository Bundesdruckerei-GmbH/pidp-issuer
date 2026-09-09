/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.AttestationProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.JwtProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.ProofType;
import de.bdr.pidp.issuer.testdata.TestAccessTokenIssuer;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RequestUtil {
    public static final String JWT_PROOF_TYPE = JwtProofType.INSTANCE.getValue();
    public static final String ATTESTATION_PROOF_TYPE = AttestationProofType.INSTANCE.getValue();

    public static final String AUTHORIZATION_VALUE = "DPoP " + TestAccessTokenIssuer.buildAccessToken().serialize();
    public static final Map<String, List<String>> HTTP_HEADER = Map.of(HttpHeaders.AUTHORIZATION.toLowerCase(), List.of(AUTHORIZATION_VALUE));

    private static final JsonMapper JSON_MAPPER = new JsonMapper();

    public static String getCredentialRequestBody(String credentialConfigurationID, String proofType, List<String> proofs) {
        return getCredentialRequestBody(credentialConfigurationID, proofType, proofs, null, null);
    }

    public static String getCredentialRequestBody(String credentialConfigurationID, String proofType, List<String> proofs, JWK resEncKAKey, EncryptionMethod resEncMethod) {
        if (resEncKAKey != null ^ resEncMethod != null) {
            throw new IllegalArgumentException("resEncKAKey & resEncMethod must both be present or omitted");
        }
        var node = JSON_MAPPER.createObjectNode();
        node.put("credential_configuration_id", credentialConfigurationID);
        var proofsNode = node.putObject("proofs");
        var proofsArrayNode = proofsNode.putArray(proofType);
        proofs.forEach(proofsArrayNode::add);
        if (resEncKAKey != null) {
            var resEncNode = node.putObject("credential_response_encryption");
            var jwkNode = JSON_MAPPER.readTree(resEncKAKey.toJSONString());
            resEncNode.set("jwk", jwkNode);
            resEncNode.put("enc", resEncMethod.getName());
        }
        return node.toString();
    }

    public static CredentialRequest createCredentialRequest(CredentialConfigurationID credID, ProofType proofType, List<String> proofs) {
        return getCredentialRequest(HTTP_HEADER, credID, proofType.getValue(), proofs);
    }

    public static CredentialRequest createCredentialRequest(CredentialConfigurationID credID, List<String> proofs) {
        return getCredentialRequest(HTTP_HEADER, credID, ATTESTATION_PROOF_TYPE, proofs);
    }

    public static CredentialRequest createCredentialRequest(CredentialConfigurationID credID, List<String> proofs, JWK resEncKAKey, EncryptionMethod resEncMethod) {
        return getCredentialRequest(HTTP_HEADER, credID, ATTESTATION_PROOF_TYPE, proofs, resEncKAKey, resEncMethod);
    }

    private static CredentialRequest getCredentialRequest(Map<String, List<String>> headers, CredentialConfigurationID credentialConfigurationID, String proofType, List<String> proofs) {
        return getCredentialRequest(headers, credentialConfigurationID, proofType, proofs, null, null);
    }

    private static CredentialRequest getCredentialRequest(Map<String, List<String>> headers, CredentialConfigurationID credentialConfigurationID, String proofType, List<String> proofs, JWK resEncKAKey, EncryptionMethod resEncMethod) {
        return new CredentialRequest(HttpMethod.POST.name(), headers, getCredentialRequestBody(credentialConfigurationID.getName(), proofType, proofs, resEncKAKey, resEncMethod));
    }
}
