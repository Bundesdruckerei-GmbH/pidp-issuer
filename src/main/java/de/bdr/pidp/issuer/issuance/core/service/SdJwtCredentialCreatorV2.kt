/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode
import de.bdr.pidp.issuer.issuance.core.StatusReference
import de.bdr.pidp.issuer.issuance.core.service.CredentialCreator.localZoneId
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwtFactory
import kotlinx.coroutines.runBlocking
import java.time.LocalDate
import java.time.Period

class SdJwtCredentialCreatorV2(
    private val issuer: String,
    private val signer: CredentialSigner,
    val maxValidity: Period,
    private val vct: String,
    format: String,
): CredentialCreator {

    private val joseType = JOSEObjectType(format)
    private val hashAlgorithm = HashAlgorithm.SHA_256

    override fun create(
        data: PIDIdentityData,
        holderBindingKey: JWK,
        status: StatusReference?,
        validity: CredentialCreator.Validity
    ): String {
        val sdJwtSigner = SdJwtSigner(signer)

        val sdJwtIssuer = NimbusSdJwtOps.issuer(
            sdJwtFactory = SdJwtFactory(hashAlgorithm = hashAlgorithm),
            signer = sdJwtSigner.signer(),
            signAlgorithm = sdJwtSigner.algorithm(),
            jwsHeaderCustomization = {
                sdJwtSigner.customizeHeader(this)
                type(joseType)
            }
        )

        val validFrom = validity.validFrom
        val validUntil = validity.validUntil

        val maxExpirationDate = LocalDate.ofInstant(validFrom, localZoneId).plus(maxValidity)
        val expirationDate = getExpirationDate(data, maxExpirationDate)

        val disclosableObject = SdJwtPIDBuilderV2()
            .defaultClaims(vct, issuer, holderBindingKey, status)
            .validity(validFrom, validUntil)
            .issuingCountry(ISO3166_1Alpha2CountryCode.DE)
            .personalData(data)
            .expiration(expirationDate)
            .build()

        val serialized = with(NimbusSdJwtOps) {
            runBlocking { sdJwtIssuer.issue(disclosableObject) }.getOrThrow().serialize()
        }

        return serialized
    }
}
