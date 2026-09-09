/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import com.upokecenter.cbor.CBORObject;
import de.bdr.pidp.issuer.base.BirthDate;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.LocalDate;
import java.util.HashMap;

import static de.bdr.pidp.issuer.issuance.util.CountryCodeMapper.convertCountryCode;

public class MdocPIDNamespaceBuilderV3Beta extends MdocPIDNamespaceBuilderV2 {

    private static final String ABSENT_VALUE_DEFAULT = "";
    private static final int CBOR_TAG_FULL_DATE_STRING = 1004;

    public MdocPIDNamespaceBuilderV3Beta(String namespace) {
        super(namespace);
    }

    @Override
    public MdocPIDNamespaceBuilderV3Beta personalData(PIDIdentityData data) {
        items.put("family_name", getOrDefault(data.familyNames()));
        items.put("given_name", getOrDefault(data.givenNames()));
        items.put("birth_date", toCBORFullDateSanitized(data.dateOfBirth()));

        var placeOfBirth = new HashMap<String, String>();
        placeOfBirth.put("locality", switch (data.placeOfBirth()) {
            case Locality(String locality) -> locality;
            case NoPlaceInfo() -> ABSENT_VALUE_DEFAULT;
        });
        items.put("place_of_birth", placeOfBirth);

        switch (data.placeOfResidence()) {
            case StructuredPlace(String street, String city, String country, String state, String zipCode) -> {
                items.put("resident_country", convertCountryCode(country));
                items.put("resident_state", getOrDefault(state));
                items.put("resident_city", getOrDefault(city));
                items.put("resident_postal_code", getOrDefault(zipCode));
                items.put("resident_street", getOrDefault(street));
            }
            case NoPlaceInfo() -> {
                items.put("resident_country", ABSENT_VALUE_DEFAULT);
                items.put("resident_state", ABSENT_VALUE_DEFAULT);
                items.put("resident_city", ABSENT_VALUE_DEFAULT);
                items.put("resident_postal_code", ABSENT_VALUE_DEFAULT);
                items.put("resident_street", ABSENT_VALUE_DEFAULT);
            }
        }

        items.put("nationality", new String[]{convertCountryCode(data.nationality())});

        return this;
    }

    @Override
    public MdocPIDNamespaceBuilderV3Beta issuingCountry(ISO3166_1Alpha2CountryCode countryCode) {
        super.issuingCountry(countryCode);
        return this;
    }

    @Override
    public MdocPIDNamespaceBuilderV3Beta expiration(LocalDate expirationDate) {
        return this;
    }

    @Override
    public MdocPIDNamespaceBuilderV3Beta personalDataDe(PIDIdentityData data) {
        var ageInYears = data.dateOfBirth().getAgeInYears();

        items.put("age_over_12", ageInYears >= 12);
        items.put("age_over_14", ageInYears >= 14);
        items.put("age_over_16", ageInYears >= 16);
        items.put("age_over_18", ageInYears >= 18);
        items.put("age_over_21", ageInYears >= 21);
        items.put("age_over_65", ageInYears >= 65);

        items.put("birth_name", getOrDefault(data.birthName()));
        items.put("source_document_type", data.documentType());

        items.put("also_known_as", getOrDefault(data.artisticName()));
        items.put("academic_title", getOrDefault(data.academicTitle()));

        items.put("raw_eid_birth_date", toCBORFullDate(data.dateOfBirth()));

        return this;
    }

    protected static CBORObject toCBORFullDateSanitized(BirthDate date) {
        return CBORObject.FromObjectAndTag(date.toSanitizedIsoDateString(), CBOR_TAG_FULL_DATE_STRING);
    }

    private static @NonNull String getOrDefault(@Nullable String value) {
        return value == null ? ABSENT_VALUE_DEFAULT : value;
    }
}
