/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import de.bdr.pidp.issuer.base.jwt.RemoteSigner
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x509.IssuerSerial

internal class SdJwtSigner(signer: CredentialSigner) {

    private val jwsSigner = RemoteSigner(setOf(signer.algorithm.jwsAlgorithm), signer::sign)

    private val algorithm = signer.algorithm.jwsAlgorithm

    private val certChain = signer.certificateChain

    init {
        check(certChain.isNotEmpty()) { "Signer must not return an empty cert chain" }
    }

    private val encodedCertChain = listOf(certChain[0].encoded)

    private val kid = Certificate.getInstance(encodedCertChain[0]).let {
        java.util.Base64.getEncoder()
            .encodeToString(IssuerSerial(it.issuer, it.serialNumber.value).encoded)
    }

    fun customizeHeader(builder: JWSHeader.Builder) {
        header(builder)
    }

    fun header(
        builder: JWSHeader.Builder = JWSHeader.Builder(algorithm)
    ): JWSHeader.Builder {

        builder.x509CertChain(encodedCertChain.map { Base64.encode(it) })

        builder.keyID(kid)

        return builder
    }

    fun signer() = jwsSigner
    fun algorithm() = algorithm
}
