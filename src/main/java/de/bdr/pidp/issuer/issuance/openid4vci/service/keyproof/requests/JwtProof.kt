/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

object JwtProofType : ProofType {
    override val value = "jwt"
}

@Serializable
data class JwtProof
@OptIn(ExperimentalSerializationApi::class)
constructor(
    val jwt: String,
    @SerialName("proof_type") @EncodeDefault override val proofType: ProofType = JwtProofType,
) : Proof {

    init {
        require(proofType == JwtProofType) { "Proof type must be JwtProofType" }
    }

    @Transient
    val signedJwt =
        try {
            SignedJWT.parse(jwt)
        } catch (e: Exception) {
            throw ProofParseException("Failed to parse jwt", e)
        }
}
