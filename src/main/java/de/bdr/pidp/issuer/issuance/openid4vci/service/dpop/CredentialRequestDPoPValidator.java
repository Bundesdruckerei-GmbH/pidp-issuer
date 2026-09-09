/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationDiscoveryAdapter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.stereotype.Component;
import org.springframework.web.util.InvalidUrlException;

import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.IssuanceDPoPValidationException.invalidDPoPProof;

@Slf4j
@Component
public class CredentialRequestDPoPValidator {
    private final Set<JWSAlgorithm> acceptedAlgs;

    private final DPoPProtectedResourceRequestVerifier resourceRequestVerifier;
    private final Duration proofTimeTolerance;
    private final URI credentialRequestUrl;

    public CredentialRequestDPoPValidator(IssuanceConfiguration config, CredentialIssuerMetadata metadata, AuthorizationDiscoveryAdapter discovery) {
        proofTimeTolerance = config.getProofTimeTolerance();
        long proofMaxAgeSeconds = config.getProofValidity().plus(proofTimeTolerance).toSeconds();
        acceptedAlgs = Set.copyOf(discovery.getDPoPSigningAlgorithms());
        credentialRequestUrl = metadata.credentialEndpoint();
        resourceRequestVerifier = new DPoPProtectedResourceRequestVerifier(acceptedAlgs, proofTimeTolerance.toSeconds(), proofMaxAgeSeconds, null);
    }

    public void validateResourceRequestDPoPProof(SignedJWT accessToken, List<String> dpopHeader, String requestMethod,
                                                 de.bdr.pidp.issuer.base.Nonce acceptedDPoPNonce,
                                                 JWKThumbprintConfirmation jwkThumbprintConfirmation) {
        SignedJWT dpopProof = getDPoPProofAsSignedJwt(dpopHeader);
        val nonce = validateAndParseNonce(acceptedDPoPNonce);

        try {
            resourceRequestVerifier.verify(
                    requestMethod,
                    credentialRequestUrl,
                    // is only used with the singleUseChecker to map a client by its id to the already used jti (JWT ID)
                    new DPoPIssuer("client_id dummy"),
                    dpopProof,
                    new DPoPAccessToken(accessToken.serialize()),
                    jwkThumbprintConfirmation,
                    nonce
            );
        } catch (AccessTokenValidationException | InvalidDPoPProofException | JOSEException | InvalidUrlException e) {
            log.debug(e.getMessage(), e);
            throw invalidDPoPProof(acceptedAlgs);
        }
    }

    private Nonce validateAndParseNonce(de.bdr.pidp.issuer.base.Nonce dpopNonce) {
        if (Instant.now().minus(proofTimeTolerance).isAfter(dpopNonce.expirationTime())) {
            throw invalidDPoPProof(acceptedAlgs, "DPoP nonce is expired");
        }
        return Nonce.parse(dpopNonce.nonce());
    }

    private SignedJWT getDPoPProofAsSignedJwt(List<String> dpopHeaders) {
        if (dpopHeaders == null) {
            throw invalidDPoPProof(acceptedAlgs, "DPoP header missing");
        }
        if (dpopHeaders.size() > 1) {
            throw invalidDPoPProof(acceptedAlgs, "DPoP header contains more than one element");
        }
        var dpop = dpopHeaders.getFirst();
        return parseDPoPToken(dpop);
    }

    private SignedJWT parseDPoPToken(String dpopHeader) {
        try {
            SignedJWT dpopToken = SignedJWT.parse(dpopHeader);
            if (!dpopToken.getJWTClaimsSet().getClaims().containsKey("nonce")) {
                throw new MissingDPoPNonceException(acceptedAlgs);
            }
            return dpopToken;
        } catch (ParseException e) {
            log.debug(e.getMessage(), e);
            throw invalidDPoPProof(acceptedAlgs, "DPoP is not a valid JWT");
        }
    }
}
