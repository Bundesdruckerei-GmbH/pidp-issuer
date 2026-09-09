/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.dpop;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.OIDException;
import lombok.Getter;
import lombok.val;

import java.util.Set;

import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_NONCE_HEADER;

@Getter
public class IssuanceDPoPValidationException extends OIDException {
    public static final String REALM = "oid4vci";

    private final DPoPTokenError error;

    public IssuanceDPoPValidationException(DPoPTokenError error) {
        super(error.getCode(), error.getDescription());
        this.error = error;
    }

    public static IssuanceDPoPValidationException invalidDPoPProof(Set<JWSAlgorithm> acceptedAlgs, String description) {
        return new IssuanceDPoPValidationException(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedAlgs).setRealm(REALM).setDescription(description));
    }

    public static IssuanceDPoPValidationException invalidDPoPProof(Set<JWSAlgorithm> acceptedAlgs) {
        return new IssuanceDPoPValidationException(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedAlgs).setRealm(REALM));
    }

    public static IssuanceDPoPValidationException useDPoPNonce(Set<JWSAlgorithm> acceptedAlgs, String nonce) {
        val ex = new IssuanceDPoPValidationException(DPoPTokenError.USE_DPOP_NONCE.setJWSAlgorithms(acceptedAlgs).setRealm(REALM));
        ex.addHeader(DPOP_NONCE_HEADER, nonce);
        return ex;
    }
}
