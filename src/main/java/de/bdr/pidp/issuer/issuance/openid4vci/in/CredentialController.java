/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CredentialService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import lombok.RequiredArgsConstructor;
import org.jmolecules.architecture.hexagonal.PrimaryAdapter;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

@PrimaryAdapter
@RestController
@RequiredArgsConstructor
public class CredentialController {

    private final IssuanceRequestFactory httpAdapter;
    private final CNonceService cNonceService;
    private final CredentialService credentialService;

    @PostMapping(path = "nonce", produces = "application/json")
    public ResponseEntity<JsonNode> issueNonce() {
        Nonce nonce = cNonceService.provide();

        return ResponseEntity.ok(cNonceService.toJsonNode(nonce));
    }

    @PostMapping(path = "credential", consumes = "application/json", produces = "application/json")
    public ResponseEntity<JsonNode> issueCredential(@RequestHeader MultiValueMap<String, String> allHeaders, @Nullable @RequestBody String body) {
        CredentialRequest credentialRequest = httpAdapter.getCredentialRequest(HttpMethod.POST, false, allHeaders, body);

        var response = credentialService.processCredentialRequest(credentialRequest);

        return IssuanceResponseFactory.createCredentialResponse(response);
    }

    @PostMapping(path = "credential", consumes = "application/jwt")
    public ResponseEntity<?> issueCredentialEnc(@RequestHeader MultiValueMap<String, String> allHeaders, @Nullable @RequestBody String body) {
        CredentialRequest credentialRequest = httpAdapter.getCredentialRequest(HttpMethod.POST, true, allHeaders, body);

        if (credentialRequest.getCredentialEncryption() != null) {
            var response = credentialService.processCredentialRequestWithResponseEnc(credentialRequest);
            return IssuanceResponseFactory.createEncryptedCredentialResponse(response);
        }

        var response = credentialService.processCredentialRequest(credentialRequest);
        return IssuanceResponseFactory.createCredentialResponse(response);
    }
}
