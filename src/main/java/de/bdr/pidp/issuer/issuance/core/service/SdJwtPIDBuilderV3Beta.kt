/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode
import de.bdr.pidp.issuer.issuance.core.StatusReference
import de.bdr.pidp.issuer.issuance.util.CountryCodeMapper.convertCountryCode
import java.time.Instant
import java.time.LocalDate

open class SdJwtPIDBuilderV3Beta: SdJwtPIDBuilderV2() {

    companion object {
        private const val ABSENT_VALUE_DEFAULT: String = ""
    }

    override fun issuingCountry(countryCode: ISO3166_1Alpha2CountryCode): SdJwtPIDBuilderV3Beta {
        return super.issuingCountry(countryCode) as SdJwtPIDBuilderV3Beta
    }

    override fun defaultClaims(
        vct: String,
        issuer: String,
        holderBindingKey: JWK,
        status: StatusReference?
    ): SdJwtPIDBuilderV3Beta {
        return super.defaultClaims(vct, issuer, holderBindingKey, status) as SdJwtPIDBuilderV3Beta
    }

    override fun validity(validFrom: Instant, validUntil: Instant): SdJwtPIDBuilderV3Beta {
        return super.validity(validFrom, validUntil) as SdJwtPIDBuilderV3Beta
    }

    override fun personalData(data: PIDIdentityData): SdJwtPIDBuilderV3Beta {
        val age = data.dateOfBirth.ageInYears

        builder.sdClaim("family_name", data.familyNames ?: ABSENT_VALUE_DEFAULT)
        builder.sdClaim("given_name", data.givenNames ?: ABSENT_VALUE_DEFAULT)
        builder.sdClaim("birth_name", data.birthName ?: ABSENT_VALUE_DEFAULT)

        builder.sdClaim("birthdate", data.dateOfBirth.toSanitizedIsoDateString())
        builder.sdClaim("source_document_type", data.documentType)
        builder.sdClaim("raw_eid_birth_date", data.dateOfBirth.toIsoDateString())

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
                    }
                    is NoPlaceInfo -> {
                        sdClaim("locality", ABSENT_VALUE_DEFAULT)
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

    override fun expiration(expirationDate: LocalDate): SdJwtPIDBuilderV3Beta {
        return this
    }
}
