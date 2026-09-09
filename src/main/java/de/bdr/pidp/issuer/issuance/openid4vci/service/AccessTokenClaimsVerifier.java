/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.jwt.InsufficientScopeException;
import de.bdr.pidp.issuer.base.jwt.JWTClaimsVerifier;
import org.jspecify.annotations.NullMarked;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@NullMarked
public class AccessTokenClaimsVerifier extends JWTClaimsVerifier<AccessTokenSecurityContext> {

    private final Issuer credentialIssuer;

    public AccessTokenClaimsVerifier(Issuer credentialIssuer, int maxClockSkew) {
        setMaxClockSkew(maxClockSkew);
        this.credentialIssuer = credentialIssuer;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, AccessTokenSecurityContext context) throws BadJWTException {
        verifyTimeClaims(claimsSet);

        verifyIssuerClaim(claimsSet, context.getAuthServer());

        verifyAudienceClaim(claimsSet, credentialIssuer.getValue());

        verifySubjectClaimExists(claimsSet);

        verifyJWTIDClaimExists(claimsSet);

        verifyClientIDClaim(claimsSet);

        verifyScopeClaim(claimsSet, context.getScope());

        verifySeedCredentialRefClaim(claimsSet);

        verifyConfirmationThumbprintClaimExists(claimsSet);

        verifyRefreshTokenRefClaim(claimsSet);
    }

    private void verifyTimeClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        var now = new Date();

        verifyIssuedAtClaim(claimsSet, now);

        verifyExpirationClaim(claimsSet, now);
    }

    private void verifyIssuerClaim(JWTClaimsSet claimsSet, Issuer expected) throws BadJWTException {
        final String iss = claimsSet.getIssuer();

        if (iss == null || iss.isBlank()) {
            throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
        }

        if (!iss.equals(expected.getValue())) {
            throw new BadJWTException("JWT issuer does not match expected value");
        }
    }

    private void verifyClientIDClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        final String clientID;
        try {
            clientID = claimsSet.getStringClaim(AccessTokenClaims.CLIENT_ID);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT client ID (%s) claim".formatted(AccessTokenClaims.CLIENT_ID), e);
        }

        if (clientID == null || clientID.isBlank()) {
            throw new BadJWTException("Missing JWT client ID (%s) claim".formatted(AccessTokenClaims.CLIENT_ID));
        }

        try {
            UUID.fromString(clientID);
        } catch (IllegalArgumentException e) {
            throw new BadJWTException("Invalid JWT client ID (%s) format".formatted(AccessTokenClaims.CLIENT_ID), e);
        }
    }

    private void verifyScopeClaim(JWTClaimsSet claimsSet, Scope expected) throws BadJWTException {
        final String scopeString;
        try {
            scopeString = claimsSet.getStringClaim(AccessTokenClaims.SCOPE);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT scope (%s) claim".formatted(AccessTokenClaims.SCOPE), e);
        }

        var scope = Scope.parse(scopeString);
        if (scope == null || scope.isEmpty()) {
            throw new BadJWTException("Missing JWT scope (%s) claim".formatted(AccessTokenClaims.SCOPE));
        }

        if (!scope.containsAll(expected)) {
            throw new InsufficientScopeException(expected);
        }
    }

    private void verifySeedCredentialRefClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        final String seedRef;
        try {
            seedRef = claimsSet.getStringClaim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT seed credential ref (%s) claim".formatted(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE), e);
        }

        if (seedRef == null || seedRef.isBlank()) {
            throw new BadJWTException("Missing JWT seed credential ref (%s) claim".formatted(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE));
        }

        try {
            UUID.fromString(seedRef);
        } catch (IllegalArgumentException e) {
            throw new BadJWTException("Invalid JWT seed credential ref (%s) format".formatted(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE), e);
        }
    }

    private void verifyRefreshTokenRefClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        final String refreshTokenRef;
        try {
            refreshTokenRef = claimsSet.getStringClaim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT refresh token ref (%s) claim".formatted(AccessTokenClaims.REFRESH_TOKEN_REFERENCE), e);
        }

        if (refreshTokenRef == null || refreshTokenRef.isBlank()) {
            throw new BadJWTException("Missing JWT refresh token ref (%s) claim".formatted(AccessTokenClaims.REFRESH_TOKEN_REFERENCE));
        }

        try {
            UUID.fromString(refreshTokenRef);
        } catch (IllegalArgumentException e) {
            throw new BadJWTException("Invalid JWT refresh token ref (%s) format".formatted(AccessTokenClaims.REFRESH_TOKEN_REFERENCE), e);
        }
    }

    private void verifyConfirmationThumbprintClaimExists(JWTClaimsSet claimsSet) throws BadJWTException {
        final JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.parse(claimsSet);

        if (cnf == null) {
            throw new BadJWTException("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
        }
    }
}
