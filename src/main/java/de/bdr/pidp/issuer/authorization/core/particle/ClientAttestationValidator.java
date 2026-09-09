/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.particle.clientattestation.ClientAttestationVerifier;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ClientAttestationValidator {

    private final ClientAttestationVerifier clientAttestationVerifier;
    private final ClientConfigurationService clientConfigurationService;

    public AttestationValues validateClientAttestation(SignedJWT attestation, SignedJWT attestationPoP, String clientId) {
        var clientAttestationCert = clientConfigurationService.getClientAttestationCerts(UUID.fromString(clientId));
        var values = clientAttestationVerifier.verify(attestation, attestationPoP, clientAttestationCert, clientId);
        return new AttestationValues(values.confirmationKey(), values.statusListRef());
    }

    public record AttestationValues(JWK confirmationKey, @Nullable StatusListRef statusListRef) {
    }
}
