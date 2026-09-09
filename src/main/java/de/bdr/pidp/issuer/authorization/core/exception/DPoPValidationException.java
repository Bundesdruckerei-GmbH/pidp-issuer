/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import lombok.Getter;
import lombok.val;

import java.util.Set;

import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_NONCE_HEADER;

@Getter
public class DPoPValidationException extends OAuthException {
    private static final String REALM = "oid4vci";

    private final DPoPTokenError error;

    public DPoPValidationException(DPoPTokenError error) {
        super(error.getCode(), error.getDescription());
        this.error = error;
    }

    public static DPoPValidationException invalidDPoPProof(Set<JWSAlgorithm> acceptedAlgs, String description) {
        return new DPoPValidationException(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedAlgs).setRealm(REALM).setDescription(description));
    }

    public static DPoPValidationException invalidDPoPProof(Set<JWSAlgorithm> acceptedAlgs) {
        return new DPoPValidationException(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedAlgs).setRealm(REALM));
    }

    public static DPoPValidationException useDPoPNonce(Set<JWSAlgorithm> acceptedAlgs, String nonce) {
        val ex = new DPoPValidationException(DPoPTokenError.USE_DPOP_NONCE.setJWSAlgorithms(acceptedAlgs).setRealm(REALM));
        ex.addHeader(DPOP_NONCE_HEADER, nonce);
        return ex;
    }
}
