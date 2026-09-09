/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidCredentialRequestException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.Proof;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.SupportedProofTypes;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

public abstract class KeyProofHandler<T extends Proof> {

    protected final int maxKeysSize;

    KeyProofHandler(CredentialIssuerMetadata metadata) {
        maxKeysSize = metadata.evaluateMaxBatchSize();
    }

    public abstract SupportedProofTypes forProofType();

    public abstract T asInstanceOf(Proof proof);

    public Collection<JWK> validateAndGetJwks(CredentialRequest request, String clientId) {
        if (clientId ==  null) {
            throw new PidServerException("clientId not found");
        }

        var proofs = request.getProofs();
        checkProofs(proofs);

        if (readProofType(proofs) == forProofType()) {
            var typeProofs = proofs.stream().map(this::asInstanceOf).toList();
            return validateAndGetProofs(clientId, request.getCredentialConfigurationID(), typeProofs);
        }
        return Collections.emptyList();
    }

    public abstract Collection<JWK> validateAndGetProofs(String clientId, CredentialConfigurationID credentialID, List<T> proofs);

    private SupportedProofTypes readProofType(List<Proof> proofs) {
        return SupportedProofTypes.findByName(proofs.getFirst().getProofType().getValue());
    }

    private void checkProofs(Collection<Proof> proofs) {
        if (maxKeysSize == 0 && !proofs.isEmpty()) {
            throw new InvalidCredentialRequestException("No proofs expected");
        }
        if (proofs.size() > maxKeysSize) {
            throw new InvalidProofException("Too many proofs");
        }
        if (proofs.isEmpty()) {
            throw new InvalidProofException("Proof is missing");
        }
    }
}
