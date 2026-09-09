/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.util.Base64URL;

import java.util.Set;
import java.util.function.Function;
import java.util.function.UnaryOperator;

public class RemoteSigner extends BaseJWSProvider implements JWSSigner {

    final Function<byte[], Base64URL> remoteSignFunction;

    /**
     * @param remoteSignFunction provides the hash that is to be signed
     */
    public RemoteSigner(Set<JWSAlgorithm> algs, Function<byte[], Base64URL> remoteSignFunction) {
        super(algs);
        this.remoteSignFunction = remoteSignFunction;
    }

    /**
     * @param remoteSignFunction provides the hash that is to be signed
     */
    public RemoteSigner(Set<JWSAlgorithm> algs, UnaryOperator<byte[]> remoteSignFunction) {
        this(algs, remoteSignFunction.andThen(Base64URL::encode));
    }


    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!this.supportedJWSAlgorithms().contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, this.supportedJWSAlgorithms()));
        }

        return remoteSignFunction.apply(signingInput);
    }
}
