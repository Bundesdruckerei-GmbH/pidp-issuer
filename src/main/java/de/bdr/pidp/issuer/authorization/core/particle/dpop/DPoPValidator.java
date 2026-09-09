/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPTokenRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionDPoPView;
import de.bdr.pidp.issuer.authorization.core.particle.keyattestation.DPoPKeyAttestationVerifier;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException.invalidDPoPProof;
import static de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException.useDPoPNonce;

@Slf4j
@NullMarked
@Service
public class DPoPValidator {
    private static final String CLIENT_ID_DUMMY = "client_id dummy";

    private final Set<JWSAlgorithm> acceptedAlgs;

    private final DPoPNonceService nonceService;
    private final DPoPTokenRequestVerifier tokenRequestVerifier;
    private final Duration proofTimeTolerance;
    private final ClientConfigurationService clientConfigurationService;
    private final DPoPKeyAttestationVerifier keyAttestationVerifier;
    private final Set<String> disabledClients;

    public DPoPValidator(AuthorizationConfiguration config, ReadOnlyAuthMetadata metadata, DPoPNonceService nonceService, ClientConfigurationService clientConfigurationService, DPoPKeyAttestationVerifier keyAttestationVerifier) {
        this.nonceService = nonceService;
        this.clientConfigurationService = clientConfigurationService;
        this.acceptedAlgs = Set.copyOf(metadata.getDPoPJWSAlgs());
        this.proofTimeTolerance = config.getProofTimeTolerance();
        long proofMaxAgeSeconds = config.getProofValidity().plus(proofTimeTolerance).toSeconds();
        tokenRequestVerifier = new DPoPTokenRequestVerifier(acceptedAlgs, metadata.getTokenEndpointURI(), proofTimeTolerance.toSeconds(), proofMaxAgeSeconds, null);
        this.keyAttestationVerifier = keyAttestationVerifier;
        this.disabledClients = clientConfigurationService.getDisabledKeyAttestationClientsForTokenRequest();
    }

    public JWKThumbprintConfirmation validateDPoPProof(@Nullable List<String> dpopHeaders, AuthSessionDPoPView session, boolean validateKeyAttestation, String clientId) {
        val dpopProof = getDPoPProof(dpopHeaders, session);
        val nonce = getNonce(session);

        JWKThumbprintConfirmation cnf;
        try {
            cnf = tokenRequestVerifier.verify(
                // is only used with the singleUseChecker to map a client by its id to the already used jti (JWT ID)
                new DPoPIssuer(CLIENT_ID_DUMMY),
                dpopProof,
                nonce
            );
        } catch (InvalidDPoPProofException | JOSEException e) {
            log.debug(e.getMessage(), e);
            throw invalidDPoPProof(acceptedAlgs);
        }

        if (validateKeyAttestation && !disabledClients.contains(clientId)) {
            validateKeyAttestation(dpopProof, clientId);
        }

        return cnf;
    }

    private void validateKeyAttestation(SignedJWT dpop, String clientIdString) {
        final String jwt;
        try {
            jwt = dpop.getJWTClaimsSet().getStringClaim("key_attestation");
        } catch (ParseException _) {
            throw invalidDPoPProof(acceptedAlgs, "key_attestation is invalid.");
        }
        if (jwt == null) {
            throw invalidDPoPProof(acceptedAlgs, "key_attestation is missing.");
        }
        try {
            var keyAttestation = SignedJWT.parse(jwt);
            var clientId = UUID.fromString(clientIdString);
            var keyAttestationCert = clientConfigurationService.getKeyAttestationCerts(clientId);
            var attestedKeys = keyAttestationVerifier.verify(keyAttestation, keyAttestationCert);
            if (attestedKeys.size() != 1) {
                throw invalidDPoPProof(acceptedAlgs, "attested_keys does not contains exactly one key.");
            }
            if (!dpop.getHeader().getJWK().computeThumbprint().equals(attestedKeys.getFirst().computeThumbprint())) {
                throw invalidDPoPProof(acceptedAlgs, "attested key is not equals to DPoP JWK.");
            }
        } catch (ParseException e) {
            log.debug(e.getMessage(), e);
            throw invalidDPoPProof(acceptedAlgs, e.getMessage());
        } catch (JOSEException e) {
          log.warn("Compute thumbprint failed with: {}", e.getMessage(), e);
            throw invalidDPoPProof(acceptedAlgs, "Compute thumbprint failed.");
        }
    }

    private Nonce getNonce(AuthSessionDPoPView session) {
        val nonce = nonceService.fetchFromAuthSession(session);
        if (Instant.now().minus(proofTimeTolerance).isAfter(nonce.expirationTime())) {
            throw invalidDPoPProof(acceptedAlgs, "DPoP nonce is expired");
        }
        return Nonce.parse(nonce.nonce());
    }

    SignedJWT getDPoPProof(@Nullable List<String> dpopHeaders, AuthSessionDPoPView session) {
        if (dpopHeaders == null || dpopHeaders.isEmpty()) {
            throw invalidDPoPProof(acceptedAlgs, "DPoP header missing");
        }
        if (dpopHeaders.size() > 1) {
            throw invalidDPoPProof(acceptedAlgs, "DPoP header contains more than one element");
        }
        var dpop = dpopHeaders.getFirst();
        return parseDPoPToken(dpop, session);
    }

    private SignedJWT parseDPoPToken(String dpopHeader, AuthSessionDPoPView session) {
        try {
            SignedJWT dpopToken = SignedJWT.parse(dpopHeader);
            if (!dpopToken.getJWTClaimsSet().getClaims().containsKey("nonce")) {
                throw useDPoPNonce(acceptedAlgs, nonceService.provideAndSave(session).nonce());
            }
            return dpopToken;
        } catch (ParseException e) {
            log.debug(e.getMessage(), e);
            throw invalidDPoPProof(acceptedAlgs, "DPoP is not a valid JWT");
        }
    }
}
