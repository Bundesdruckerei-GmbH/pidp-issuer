/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.security.PublicKey;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class JWKUtils {
    public static PublicKey toPublicKey(JWK jwk) throws JOSEException {
        return switch (jwk) {
            case AsymmetricJWK key -> key.toPublicKey();
            default -> throw new JOSEException("JWK is not asymmetric");
        };
    }

    public static JWK extendWithKeyID(JWK jwk, String keyID) {
        return switch (jwk) {
            case ECKey ecKey -> new ECKey.Builder(ecKey).keyID(keyID).build();
            case RSAKey rsaKey -> new RSAKey.Builder(rsaKey).keyID(keyID).build();
            case OctetKeyPair octetKeyPair -> new OctetKeyPair.Builder(octetKeyPair).keyID(keyID).build();
            case OctetSequenceKey octetSequenceKey -> new OctetSequenceKey.Builder(octetSequenceKey).keyID(keyID).build();
            default -> throw new IllegalArgumentException("Unsupported key type: " + jwk.getKeyType().getValue());
        };
    }
}
