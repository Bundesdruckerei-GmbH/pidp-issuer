/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.NonceFactory;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.openid4vci.out.persistence.CNonceAdapter;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;

@NullMarked
@Service
public class CNonceService {
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Duration cNonceLifetime;
    private final Duration proofTimeTolerance;
    private final CNonceAdapter cNonceAdapter;

    public CNonceService(IssuanceConfiguration configuration, CNonceAdapter cNonceAdapter) {
        this.cNonceLifetime = configuration.getCNonceLifetime();
        this.proofTimeTolerance = configuration.getProofTimeTolerance();
        this.cNonceAdapter = cNonceAdapter;
    }

    public Nonce provide() {
        Nonce nonce = NonceFactory.createSecureRandomNonce(cNonceLifetime);
        cNonceAdapter.createAndSave(nonce);
        return nonce;
    }

    public boolean consume(String nonceString) {
        var nonce = new Nonce(nonceString, proofTimeTolerance);
        var nowWithTolerance = Instant.now().minus(proofTimeTolerance);
        return cNonceAdapter.findAndDeleteByNonce(nonce)
                .filter(n -> n.expirationTime().isAfter(nowWithTolerance))
                .isPresent();
    }

    public JsonNode toJsonNode(Nonce nonce) {
        return objectMapper.createObjectNode()
            .put("c_nonce", nonce.nonce());
    }
}
