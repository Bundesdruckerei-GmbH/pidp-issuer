/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import de.bdr.pidp.issuer.base.jwt.JWTClaimsVerifier;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Date;

@NullMarked
public class SeedCredentialClaimsVerifier extends JWTClaimsVerifier<SecurityContext> {

    private final String issuerIdentifier;

    public SeedCredentialClaimsVerifier(String issuerIdentifier, int maxClockSkew) {
        this.issuerIdentifier = issuerIdentifier;
        setMaxClockSkew(maxClockSkew);
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, @Nullable SecurityContext context) throws BadJWTException {
        verifyTimeClaims(claimsSet);

        verifyAudienceClaim(claimsSet, issuerIdentifier);

        verifySubjectClaimExists(claimsSet);

        verifyJWTIDClaimExists(claimsSet);
    }

    private void verifyTimeClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        final Date nowRef = new Date();

        verifyIssuedAtClaim(claimsSet, nowRef);

        verifyExpirationClaim(claimsSet, nowRef);
    }
}
