/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode
import de.bdr.pidp.issuer.issuance.core.StatusReference
import de.bdr.pidp.issuer.issuance.util.CountryCodeMapper.convertCountryCode
import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeFormatter

open class SdJwtPIDBuilderV2: SdJwtPIDBuilder() {

    companion object {
        private const val ABSENT_VALUE_DEFAULT: String = ""
    }

    override fun issuingCountry(countryCode: ISO3166_1Alpha2CountryCode): SdJwtPIDBuilderV2 {
        return super.issuingCountry(countryCode) as SdJwtPIDBuilderV2
    }

    override fun defaultClaims(
        vct: String,
        issuer: String,
        holderBindingKey: JWK,
        status: StatusReference?
    ): SdJwtPIDBuilderV2 {
        return super.defaultClaims(vct, issuer, holderBindingKey, status) as SdJwtPIDBuilderV2
    }

    override fun validity(validFrom: Instant, validUntil: Instant): SdJwtPIDBuilderV2 {
        builder.claim(JWTClaimNames.NOT_BEFORE, validFrom.toEpochMilli() / 1000)
        builder.claim(JWTClaimNames.EXPIRATION_TIME, validUntil.toEpochMilli() / 1000)
        return this
    }

    override fun personalData(data: PIDIdentityData): SdJwtPIDBuilderV2 {
        val age = data.dateOfBirth.ageInYears

        builder.sdClaim("family_name", data.familyNames ?: ABSENT_VALUE_DEFAULT)
        builder.sdClaim("given_name", data.givenNames ?: ABSENT_VALUE_DEFAULT)
        builder.sdClaim("birth_name", data.birthName ?: ABSENT_VALUE_DEFAULT)

        builder.sdClaim("birthdate", data.dateOfBirth.toIsoDateString())
        builder.sdClaim("source_document_type", data.documentType)

        builder.sdArrClaim("nationalities", 2) {
            sdClaim(convertCountryCode(data.nationality))
        }

        builder.sdObjClaim("age_equal_or_over") {
            sdClaim("12", age >= 12)
            sdClaim("14", age >= 14)
            sdClaim("16", age >= 16)
            sdClaim("18", age >= 18)
            sdClaim("21", age >= 21)
            sdClaim("65", age >= 65)
        }

        data.placeOfBirth.let { placeOfBirth ->
            builder.sdObjClaim("place_of_birth") {
                when (placeOfBirth) {
                    is Locality -> {
                        sdClaim("locality", placeOfBirth.locality)
                        sdClaim("no_place_info", false)
                    }
                    is NoPlaceInfo -> {
                        sdClaim("locality", ABSENT_VALUE_DEFAULT)
                        sdClaim("no_place_info", true)
                    }
                }
            }
        }

        data.placeOfResidence.let { residence ->
            builder.sdObjClaim("address") {
                when (residence) {
                    is StructuredPlace -> {
                        sdClaim("locality", residence.city ?: ABSENT_VALUE_DEFAULT)
                        sdClaim("country", convertCountryCode(residence.country))
                        sdClaim("region", residence.state ?: ABSENT_VALUE_DEFAULT)
                        sdClaim("postal_code", residence.zipCode ?: ABSENT_VALUE_DEFAULT)
                        sdClaim("street_address", residence.street ?: ABSENT_VALUE_DEFAULT)
                    }
                    is NoPlaceInfo -> {
                        sdClaim("locality", ABSENT_VALUE_DEFAULT)
                        sdClaim("country", ABSENT_VALUE_DEFAULT)
                        sdClaim("region", ABSENT_VALUE_DEFAULT)
                        sdClaim("postal_code", ABSENT_VALUE_DEFAULT)
                        sdClaim("street_address", ABSENT_VALUE_DEFAULT)
                    }
                }
            }
        }

        builder.sdClaim("also_known_as", data.artisticName ?: ABSENT_VALUE_DEFAULT)
        builder.sdClaim("title", data.academicTitle ?: ABSENT_VALUE_DEFAULT)

        return this
    }

    open fun expiration(expirationDate: LocalDate): SdJwtPIDBuilderV2 {
        builder.sdClaim("date_of_expiry", expirationDate.format(DateTimeFormatter.ISO_LOCAL_DATE))

        return this
    }
}
