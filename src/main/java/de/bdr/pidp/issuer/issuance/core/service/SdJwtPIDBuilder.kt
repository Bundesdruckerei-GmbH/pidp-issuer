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
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObject
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import java.time.Instant
import java.util.Objects

open class SdJwtPIDBuilder {
    protected val builder = SdJwtObjectBuilder(LinkedHashMap())

    open fun defaultClaims(vct: String, issuer: String, holderBindingKey: JWK, status: StatusReference?): SdJwtPIDBuilder {
        builder.claim("vct", vct)
        builder.claim(JWTClaimNames.ISSUER, issuer)

        builder.cnf(holderBindingKey)

        if (status != null) {
            builder.objClaim("status") {
                objClaim("status_list") {
                    claim("uri", status.uri)
                    claim("idx", status.index)
                }
            }
        }
        return this
    }

    open fun validity(validFrom: Instant, validUntil: Instant): SdJwtPIDBuilder {
        builder.claim(JWTClaimNames.ISSUED_AT, validFrom.toEpochMilli() / 1000)
        builder.claim(JWTClaimNames.EXPIRATION_TIME, validUntil.toEpochMilli() / 1000)
        return this
    }

    open fun issuingCountry(countryCode: ISO3166_1Alpha2CountryCode): SdJwtPIDBuilder {
        builder.sdClaim("issuing_country", countryCode.toString())
        builder.sdClaim("issuing_authority", countryCode.toString())
        return this
    }

    open fun personalData(data: PIDIdentityData): SdJwtPIDBuilder {
        val age = data.dateOfBirth.ageInYears

        builder.sdClaim("family_name", Objects.requireNonNull(data.familyNames))
        builder.sdClaim("given_name", Objects.requireNonNull(data.givenNames))
        data.birthName?.takeIf { it.isNotEmpty() }?.let { builder.sdClaim("birth_family_name", it) }

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

        data.placeOfBirth.let {
            if (it is Locality) {
                builder.sdObjClaim("place_of_birth") {
                    sdClaim("locality", it.locality)
                }
            }
        }

        data.placeOfResidence.let { residence ->
            if (residence is StructuredPlace) {
                builder.sdObjClaim("address") {
                    residence.city?.takeIf { it.isNotEmpty() }?.let { sdClaim("locality", it) }
                    sdClaim("country", convertCountryCode(residence.country))
                    residence.state?.takeIf { it.isNotEmpty() }?.let { sdClaim("region", it) }
                    residence.zipCode?.takeIf { it.isNotEmpty() }?.let { sdClaim("postal_code", it) }
                    residence.street?.takeIf { it.isNotEmpty() }?.let { sdClaim("street_address", it) }
                }
            }
        }
        return this
    }

    fun build(): SdJwtObject {
        return SdJwtObject(builder.elements, null)
    }
}
