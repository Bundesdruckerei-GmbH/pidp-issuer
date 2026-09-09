/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.refreshtoken;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import de.bdr.pidp.issuer.base.constants.RefreshTokenClaims;
import de.bdr.pidp.issuer.base.jwt.InsufficientScopeException;
import de.bdr.pidp.issuer.base.jwt.JWTClaimsVerifier;
import org.jspecify.annotations.NullMarked;

import java.text.ParseException;
import java.util.Date;

@NullMarked
public class RefreshTokenClaimsVerifier extends JWTClaimsVerifier<RefreshTokenSecurityContext> {

    private final Issuer authorizationServer;

    public RefreshTokenClaimsVerifier(Issuer authorizationServer, int maxClockSkew) {
        setMaxClockSkew(maxClockSkew);
        this.authorizationServer = authorizationServer;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, RefreshTokenSecurityContext context) throws BadJWTException {
        verifyTimeClaims(claimsSet);

        verifyIssuerClaim(claimsSet, authorizationServer);

        verifyAudienceClaim(claimsSet, authorizationServer.getValue());

        verifySubjectClaimExists(claimsSet);

        verifyJWTIDClaimExists(claimsSet);

        verifyClientIDClaim(claimsSet, context.getClientID());

        verifyScopeClaim(claimsSet, context.getScope());

        verifySeedCredentialClaim(claimsSet);

        verifyConfirmationThumbprintClaim(claimsSet, context.getDPoPJWKThumbprint());
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

    private void verifyClientIDClaim(JWTClaimsSet claimsSet, String expected) throws BadJWTException {
        final String clientID;
        try {
            clientID = claimsSet.getStringClaim(RefreshTokenClaims.CLIENT_ID);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT client ID (%s) claim".formatted(RefreshTokenClaims.CLIENT_ID), e);
        }

        if (clientID == null || clientID.isBlank()) {
            throw new BadJWTException("Missing JWT client ID (%s) claim".formatted(RefreshTokenClaims.CLIENT_ID));
        }

        if (!clientID.equals(expected)) {
            throw new BadJWTException("JWT client ID does not match expected value");
        }
    }

    private void verifyScopeClaim(JWTClaimsSet claimsSet, Scope expected) throws BadJWTException {
        final String scopeString;
        try {
            scopeString = claimsSet.getStringClaim(RefreshTokenClaims.SCOPE);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT scope (%s) claim".formatted(RefreshTokenClaims.SCOPE), e);
        }

        var scope = Scope.parse(scopeString);
        if (scope == null || scope.isEmpty()) {
            throw new BadJWTException("Missing JWT scope (%s) claim".formatted(RefreshTokenClaims.SCOPE));
        }

        if (!scope.containsAll(expected)) {
            throw new InsufficientScopeException(expected);
        }
    }

    private void verifySeedCredentialClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        final String seedRef;
        try {
            seedRef = claimsSet.getStringClaim(RefreshTokenClaims.SEED_CREDENTIAL);
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT seed credential (%s) claim".formatted(RefreshTokenClaims.SEED_CREDENTIAL), e);
        }

        if (seedRef == null || seedRef.isBlank()) {
            throw new BadJWTException("Missing JWT seed credential (%s) claim".formatted(RefreshTokenClaims.SEED_CREDENTIAL));
        }

        try {
            EncryptedJWT.parse(seedRef);
        } catch (ParseException e) {
            throw new BadJWTException("Malformed JWT seed credential (%s)".formatted(RefreshTokenClaims.SEED_CREDENTIAL), e);
        }
    }

    private void verifyConfirmationThumbprintClaim(JWTClaimsSet claimsSet, Base64URL expectedJkt) throws BadJWTException {
        final JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.parse(claimsSet);

        if (cnf == null) {
            throw new BadJWTException("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
        }

        if (!cnf.getValue().equals(expectedJkt)) {
            throw new BadJWTException("JWT JWK thumbprint confirmation does not match expected value");
        }
    }
}
