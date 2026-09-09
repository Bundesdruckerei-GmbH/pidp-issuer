/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.config.model.SupportedProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.AttestationProof;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.Proof;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.SupportedProofTypes;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AttestationKeyProofHandler extends KeyProofHandler<AttestationProof> {

    private final Map<CredentialConfigurationID, ProofKeyAttestationVerifier> keyAttestationVerifiers;
    private final ClientConfigurationService clientConfigurationService;

    public AttestationKeyProofHandler(ClientConfigurationService clientConfigurationService, IssuanceConfiguration config, CredentialIssuerMetadata metadata, CNonceService cNonceService) {
        super(metadata);

        this.clientConfigurationService = clientConfigurationService;

        keyAttestationVerifiers = new EnumMap<>(CredentialConfigurationID.class);
        for (var entry : metadata.credentialConfigurationsSupported().entrySet()) {
            var credentialID = entry.getKey();
            var credentialConfig = entry.getValue();

            var proofTypes = credentialConfig.proofTypesSupported();
            if (proofTypes != null) {
                var attestationProofType = proofTypes.get(SupportedProofType.ATTESTATION);
                if (attestationProofType != null) {
                    var verifier = new ProofKeyAttestationVerifier(cNonceService, config, attestationProofType);
                    keyAttestationVerifiers.put(credentialID, verifier);
                }
            }
        }
    }

    @Override
    public SupportedProofTypes forProofType() {
        return SupportedProofTypes.ATTESTATION;
    }

    @Override
    public AttestationProof asInstanceOf(Proof proof) {
        if (proof instanceof AttestationProof attestationProof) {
            return attestationProof;
        }
        throw new ClassCastException();
    }

    @Override
    public Collection<JWK> validateAndGetProofs(String clientId, CredentialConfigurationID credentialID, List<AttestationProof> proofs) {
        if (proofs.size() > 1) {
            throw new InvalidProofException("Too many proofs");
        }
        var keyAttestationCert = clientConfigurationService.getKeyAttestationCerts(UUID.fromString(clientId));
        var verifier = keyAttestationVerifiers.get(credentialID);
        if (verifier == null) {
            throw new InvalidProofException("Attestation proof not supported for given credential_configuration_id");
        }
        var jwks = verifier.verify(proofs.getFirst().getSignedJwt(), keyAttestationCert, new ArrayList<>());
        if (jwks.size() > maxKeysSize) {
            throw new InvalidProofException("Too many keys");
        }
        return jwks;
    }
}
