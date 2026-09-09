/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import com.upokecenter.cbor.CBORObject;
import de.bdr.pidp.issuer.base.BirthDate;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;

import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static de.bdr.pidp.issuer.issuance.util.CountryCodeMapper.convertCountryCode;
import static java.util.stream.Collectors.toUnmodifiableMap;

@RequiredArgsConstructor
public class MdocPIDNamespaceBuilderV1 {
    private static final int CBOR_TAG_FULL_DATE_STRING = 1004;

    private final String namespace;
    protected final Map<String, @NonNull Object> items = new HashMap<>();

    public MdocPIDNamespaceBuilderV1 personalData(PIDIdentityData data) {
        var ageInYears = data.dateOfBirth().getAgeInYears();

        items.put("family_name", Objects.requireNonNull(data.familyNames()));
        items.put("given_name", Objects.requireNonNull(data.givenNames()));
        items.put("birth_date", toCBORFullDate(data.dateOfBirth()));
        items.put("age_over_12", ageInYears >= 12);
        items.put("age_over_14", ageInYears >= 14);
        items.put("age_over_16", ageInYears >= 16);
        items.put("age_over_18", ageInYears >= 18);
        items.put("age_over_21", ageInYears >= 21);
        items.put("age_over_65", ageInYears >= 65);
        items.computeIfAbsent("family_name_birth", _ -> nullIfEmpty(data.birthName()));

        if (data.placeOfBirth() instanceof Locality(String locality)) {
            var birthPlace = new HashMap<String, String>();
            birthPlace.put("locality", locality);
            items.put("birth_place", birthPlace);
        }

        if (data.placeOfResidence() instanceof StructuredPlace(String street, String city, String country, String state, String zipCode)) {
            items.put("resident_country", convertCountryCode(country));
            items.computeIfAbsent("resident_state", _ -> nullIfEmpty(state));
            items.computeIfAbsent("resident_city", _ -> nullIfEmpty(city));
            items.computeIfAbsent("resident_postal_code", _ -> nullIfEmpty(zipCode));
            items.computeIfAbsent("resident_street", _ -> nullIfEmpty(street));
        }

        items.put("nationality", new String[]{convertCountryCode(data.nationality())});
        items.put("source_document_type", data.documentType());

        return this;
    }

    public MdocPIDNamespaceBuilderV1 validity(Instant validFrom, Instant validUntil) {
        items.put("issuance_date", toDate(validFrom));
        items.put("expiry_date", toDate(validUntil));

        return this;
    }

    public MdocPIDNamespaceBuilderV1 issuingCountry(ISO3166_1Alpha2CountryCode countryCode) {
        items.put("issuing_authority", countryCode.toString());
        items.put("issuing_country", countryCode.toString());

        return this;
    }

    public Map<String, Map<String, CBORObject>> build() {
        var cborMap = toCBORMap(items);
        return Map.of(namespace, cborMap);
    }

    private static Map<String, CBORObject> toCBORMap(Map<String, Object> map) {
        return map.entrySet().stream()
            .collect(toUnmodifiableMap(Map.Entry::getKey, e -> CBORObject.FromObject(e.getValue())));
    }

    protected static CBORObject toCBORFullDate(BirthDate date) {
        return CBORObject.FromObjectAndTag(date.toIsoDateString(), CBOR_TAG_FULL_DATE_STRING);
    }

    protected static CBORObject toCBORFullDate(LocalDate date) {
        return CBORObject.FromObjectAndTag(date.format(DateTimeFormatter.ISO_LOCAL_DATE), CBOR_TAG_FULL_DATE_STRING);
    }

    protected static Date toDate(Instant dateTime) {
        var noMillis = dateTime.truncatedTo(ChronoUnit.SECONDS);
        return Date.from(noMillis);
    }

    private static String nullIfEmpty(String value) {
        return value == null || value.isEmpty() ? null : value;
    }
}
