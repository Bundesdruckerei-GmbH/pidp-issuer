/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.JwtProof;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.Proof;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.SupportedProofTypes;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class JwtKeyProofHandler extends KeyProofHandler<JwtProof> {

    private final KeyProofService keyProofService;

    public JwtKeyProofHandler(KeyProofService keyProofService, CredentialIssuerMetadata metadata) {
        super(metadata);
        this.keyProofService = keyProofService;
    }

    @Override
    public SupportedProofTypes forProofType() {
        return SupportedProofTypes.JWT;
    }

    @Override
    public JwtProof asInstanceOf(Proof proof) {
        if (proof instanceof JwtProof jwtProof) {
            return jwtProof;
        }
        throw new ClassCastException();
    }

    @Override
    public Collection<JWK> validateAndGetProofs(String clientId, CredentialConfigurationID credentialID, List<JwtProof> proofs) {
        return keyProofService.validateJwtProofs(clientId, credentialID, new ArrayList<>(), proofs);
    }
}
