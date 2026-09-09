/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import de.bdr.pidp.issuer.base.jwt.JWTClaimsVerifier;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Date;

@NullMarked
class ClientAttestationClaimsVerifier extends JWTClaimsVerifier<ClientAttestationSecurityContext> {

    ClientAttestationClaimsVerifier(int maxClockSkew) {
        setMaxClockSkew(maxClockSkew);
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, ClientAttestationSecurityContext context) throws BadJWTException {
        verifyTimeClaims(claimsSet);

        verifySubjectClaim(claimsSet, context);

        final JWK jwk = verifyConfirmationClaim(claimsSet);

        context.setKey(jwk);

        final StatusListRef statusRef = verifyStatusListRef(claimsSet);

        context.setStatusListRef(statusRef);
    }

    private void verifyTimeClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        final Date nowRef = new Date();

        verifyExpirationClaim(claimsSet, nowRef);

        verifyIssuedAtClaimIfPresent(claimsSet, nowRef);

        verifyNotBeforeClaimIfPresent(claimsSet, nowRef);
    }

    private void verifySubjectClaim(JWTClaimsSet claimsSet, ClientAttestationSecurityContext context) throws BadJWTException {
        final String sub = claimsSet.getSubject();

        if (sub == null) {
            throw BadJWTExceptions.MISSING_SUB_CLAIM_EXCEPTION;
        }

        if (!sub.equals(context.getClientId())) {
            throw new BadJWTException("JWT subject does not match client_id");
        }
    }

    private JWK verifyConfirmationClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        final ClientAttestationConfirmation cnf;

        try {
            cnf = ClientAttestationConfirmation.parse(claimsSet);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT confirmation key: " + e.getMessage());
        }

        if (cnf == null) {
            throw new BadJWTException("Missing JWT confirmation key (cnf.jwk) claim");
        }

        return cnf.getJwk();
    }

    /**
     * presence of the status list reference is optional for now
     */
    private @Nullable StatusListRef verifyStatusListRef(JWTClaimsSet claimsSet) throws BadJWTException {
        final StatusListRef ref;

        try {
            ref = StatusListRef.parse(claimsSet);
        } catch (java.text.ParseException e) {
            throw new BadJWTException("Invalid status list reference: could not be parsed", e);
        }

        return ref;
    }
}
