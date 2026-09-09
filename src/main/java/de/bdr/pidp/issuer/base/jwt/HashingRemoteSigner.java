/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.function.UnaryOperator;

public class HashingRemoteSigner extends RemoteSigner {

    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

    /**
     * @param remoteSignFunction provides the hash that is to be signed
     */
    public HashingRemoteSigner(Set<JWSAlgorithm> algs, UnaryOperator<byte[]> remoteSignFunction) {
        if (!SUPPORTED_ALGORITHMS.containsAll(algs)) {
            throw new IllegalArgumentException("Unsupported JWS algorithms");
        }
        super(algs, remoteSignFunction);
    }

    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] signingInput) throws JOSEException {
        JWSAlgorithm alg = jwsHeader.getAlgorithm();
        var hash = hash(signingInput, alg);
        return super.sign(jwsHeader, hash);
    }

    private byte[] hash(byte[] bytes, JWSAlgorithm alg) throws JOSEException {
        String hashAlg;
        if (alg == JWSAlgorithm.ES256) {
            hashAlg = "SHA-256";
        } else if (alg == JWSAlgorithm.ES384) {
            hashAlg = "SHA-384";
        } else if (alg == JWSAlgorithm.ES512) {
            hashAlg = "SHA-512";
        } else {
            throw new JOSEException("Unsupported JWS algorithm");
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Unsupported hash algorithm: " + e.getMessage(), e);
        }

        return md.digest(bytes);
    }
}
