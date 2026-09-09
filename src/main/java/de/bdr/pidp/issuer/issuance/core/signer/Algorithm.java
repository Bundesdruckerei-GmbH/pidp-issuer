/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.signer;

import COSE.AlgorithmID;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Getter;

@Getter
public enum Algorithm {
    ES256(JWSAlgorithm.ES256, AlgorithmID.ECDSA_256),
    ES384(JWSAlgorithm.ES384, AlgorithmID.ECDSA_384),
    ES512(JWSAlgorithm.ES512, AlgorithmID.ECDSA_512);

    private final JWSAlgorithm jwsAlgorithm;
    private final AlgorithmID coseAlgorithm;

    Algorithm(JWSAlgorithm jwsAlgorithm, AlgorithmID coseAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
        this.coseAlgorithm = coseAlgorithm;
    }
}
