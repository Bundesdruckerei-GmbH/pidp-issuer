/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CredentialService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class CredentialControllerTest {

    @Mock
    private IssuanceRequestFactory issuanceRequestFactory;
    @Mock
    private CNonceService cNonceService;
    @Mock
    private CredentialService credentialService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private CredentialController credentialController;

    @Test
    void returnNonceWhenIssueNonce() {
        Nonce nonce = new Nonce("nonce", Duration.ofHours(1L));
        ObjectNode cNonceJson = objectMapper.createObjectNode()
            .put("c_nonce", nonce.nonce());
        doReturn(nonce).when(cNonceService).provide();
        doReturn(cNonceJson).when(cNonceService).toJsonNode(nonce);

        ResponseEntity<JsonNode> response = credentialController.issueNonce();

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("c_nonce").asString()).isEqualTo(nonce.nonce());
        assertThat(response.getBody().get("c_nonce_expires_in")).isNull();
    }
}
