/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.signer

import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import java.security.PrivateKey
import java.security.Signature

abstract class JcaKeyBasedCredentialSigner : CredentialSigner {

    protected abstract val privateKey: PrivateKey

    protected abstract val supportedAlgorithm: SupportedAlgorithm

    override fun getAlgorithm() = supportedAlgorithm.algorithm

    override fun sign(data: ByteArray) = sign(supportedAlgorithm.jcaAlgorithm, data)

    private fun sign(jcaAlgorithm: String, data: ByteArray): ByteArray {
        val signature = Signature.getInstance(jcaAlgorithm)
        signature.initSign(privateKey)
        signature.update(data)
        val derSig = signature.sign()
        val byteArrayLength = ECDSA.getSignatureByteArrayLength(algorithm.jwsAlgorithm)
        return ECDSA.transcodeSignatureToConcat(derSig, byteArrayLength)
    }

    enum class SupportedAlgorithm(
        val curve: Curve,
        val algorithm: Algorithm,
        val jcaAlgorithm: String
    ) {
        ES256(Curve.P_256, Algorithm.ES256, "SHA256WithECDSA"),
        ES384(Curve.P_384, Algorithm.ES384, "SHA384WithECDSA"),
        ES512(Curve.P_521, Algorithm.ES512, "SHA512WithECDSA")
    }
}
