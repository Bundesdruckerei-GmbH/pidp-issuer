/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import lombok.Getter;
import lombok.Setter;
import org.jspecify.annotations.NullMarked;

import java.util.Date;
import java.util.List;

@NullMarked
public abstract class JWTClaimsVerifier<T extends SecurityContext> implements JWTClaimsSetVerifier<T>, ClockSkewAware {

    @Getter
    @Setter
    private int maxClockSkew;


    protected void verifyIssuedAtClaim(JWTClaimsSet claimsSet, Date nowRef) throws BadJWTException {
        final Date iat = claimsSet.getIssueTime();

        if (iat == null) {
            throw BadJWTExceptions.MISSING_IAT_CLAIM_EXCEPTION;
        }

        if (!(DateUtils.isBefore(iat, nowRef, maxClockSkew))) {
            throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION;
        }
    }

    protected void verifyIssuedAtClaimIfPresent(JWTClaimsSet claimsSet, Date nowRef) throws BadJWTException {
        final Date iat = claimsSet.getIssueTime();

        if (iat != null && !DateUtils.isBefore(iat, nowRef, maxClockSkew)) {
            throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION;
        }
    }

    protected void verifyExpirationClaim(JWTClaimsSet claimsSet, Date nowRef) throws BadJWTException {
        final Date exp = claimsSet.getExpirationTime();

        if (exp == null) {
            throw BadJWTExceptions.MISSING_EXP_CLAIM_EXCEPTION;
        }

        if (!DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
            throw BadJWTExceptions.EXPIRED_EXCEPTION;
        }
    }

    protected void verifyExpirationClaimIfPresent(JWTClaimsSet claimsSet, Date nowRef) throws BadJWTException {
        final Date exp = claimsSet.getExpirationTime();

        if (exp != null && !DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
            throw BadJWTExceptions.EXPIRED_EXCEPTION;
        }
    }

    protected void verifyNotBeforeClaimIfPresent(JWTClaimsSet claimsSet, Date nowRef) throws BadJWTException {
        final Date nbf = claimsSet.getNotBeforeTime();

        if (nbf != null && !DateUtils.isBefore(nbf, nowRef, maxClockSkew)) {
            throw new BadJWTException("JWT before use time");
        }
    }

    protected void verifyAudienceClaim(JWTClaimsSet claimsSet, String expected) throws BadJWTException {
        final List<String> aud = claimsSet.getAudience();

        if (aud == null || aud.isEmpty()) {
            throw BadJWTExceptions.MISSING_AUD_CLAIM_EXCEPTION;
        }

        if (!aud.contains(expected)) {
            throw new BadJWTException("JWT audience unknown");
        }
    }

    protected void verifyJWTIDClaimExists(JWTClaimsSet claimsSet) throws BadJWTException {
        final String jti = claimsSet.getJWTID();

        if (jti == null) {
            throw new BadJWTException("Missing JWT JWTID (jti) claim");
        }

        if (jti.isBlank()) {
            throw new BadJWTException("JWT JWTID empty");
        }
    }

    protected void verifySubjectClaimExists(JWTClaimsSet claimsSet) throws BadJWTException {
        final var sub = claimsSet.getSubject();

        if (sub == null || sub.isEmpty()) {
            throw BadJWTExceptions.MISSING_SUB_CLAIM_EXCEPTION;
        }
    }
}
