/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import de.bdr.pidp.issuer.base.jwt.JWTClaimsVerifier;
import org.jspecify.annotations.NullMarked;

import java.text.ParseException;
import java.util.Date;

@NullMarked
class ClientAttestationPoPClaimsVerifier extends JWTClaimsVerifier<ClientAttestationSecurityContext> {

    private final String issuerIdentifier;

    ClientAttestationPoPClaimsVerifier(String issuerIdentifier, int maxClockSkew) {
        this.issuerIdentifier = issuerIdentifier;
        setMaxClockSkew(maxClockSkew);
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, ClientAttestationSecurityContext context) throws BadJWTException {
        verifyTimeClaims(claimsSet);

        verifyIssuerClaim(claimsSet, context);

        verifyAudienceClaim(claimsSet, issuerIdentifier);

        verifyJWTIDClaimExists(claimsSet);

        verifyChallengeClaim(claimsSet, context);
    }

    private void verifyTimeClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        final Date nowRef = new Date();

        verifyIssuedAtClaim(claimsSet, nowRef);

        verifyNotBeforeClaimIfPresent(claimsSet, nowRef);
    }

    private void verifyIssuerClaim(JWTClaimsSet claimsSet, ClientAttestationSecurityContext context) throws BadJWTException {
        final String iss = claimsSet.getIssuer();

        if (iss == null) {
            throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
        }

        if (!iss.equals(context.getClientId())) {
            throw new BadJWTException("JWT issuer does not match client_id");
        }
    }

    private void verifyChallengeClaim(JWTClaimsSet claimsSet, ClientAttestationSecurityContext context) throws BadJWTException {
        var challengeCheck = context.getChallengeCheck();
        if (challengeCheck != null) {
            final String challenge;
            try {
                challenge = claimsSet.getStringClaim("challenge");
            } catch (ParseException e) {
                throw new BadJWTException("Invalid JWT challenge (challenge) claim", e);
            }

            if (challenge == null) {
                return; // not required for now
            }

            if (!challengeCheck.test(Nonce.parse(challenge))) {
                throw new BadJWTException("Unknown or expired JWT challenge");
            }
        }
    }
}
