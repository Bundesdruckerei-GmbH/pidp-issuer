/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.policy;


import de.bdr.pidp.issuer.base.BirthDate;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.issuance.util.CountryCodeMapper;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class PidIdentityDataValidator {
    private static final String ISO_DATE_FORMAT = "yyyy-MM-dd";
    private static final int MAX_STR_LENGTH = 150;

    public static IssuanceDecision validatePidIdentityData(IdentityData identityData) {
        Set<String> validationFailures = new HashSet<>();

        DocumentType.validateDocumentType(identityData.documentType()).ifPresent(error -> validationFailures.add("Identity data: " + error));
        validateBirthDateString(identityData.dateOfBirth()).ifPresent(validationFailures::add);
        validatePlaceOfBirth(identityData.placeOfBirth()).ifPresent(validationFailures::add);
        validateNationality(identityData.nationality(), identityData.documentType()).ifPresent(validationFailures::add);
        validatePlaceOfResidence(identityData.placeOfResidence()).ifPresent(validationFailures::add);
        validateRestrictedId(identityData.restrictedId()).ifPresent(validationFailures::add);
        validateDateOfExpiry(identityData.dateOfExpiry()).ifPresent(validationFailures::add);

        validateLettersLength(identityData.givenNames(), "given names").ifPresent(validationFailures::add);
        validateLettersLength(identityData.familyNames(), "family names").ifPresent(validationFailures::add);
        validateLettersLength(identityData.artisticName(), "artistic name").ifPresent(validationFailures::add);
        validateLettersLength(identityData.academicTitle(), "academic title").ifPresent(validationFailures::add);
        validateLettersLength(identityData.birthName(), "birth name").ifPresent(validationFailures::add);
        validateLettersLength(identityData.placeOfBirth(), "place of birth", validationFailures);
        validateLettersLength(identityData.placeOfResidence(), "place of residence", validationFailures);

        if (validationFailures.isEmpty()) {
            return new ValidIssuanceDecision();
        } else  {
            return new InvalidIssuanceDecision(validationFailures);
        }
    }

    private static int countLetters(String s) {
        return s.codePointCount(0, s.length());
    }

    private static Optional<String> validateLettersLength(@Nullable String data, String propertyName) {
        return data != null && countLetters(data) > MAX_STR_LENGTH ? Optional.of("'%s' exceeds the maximum text length".formatted(propertyName)) : Optional.empty();
    }

    private static void validateLettersLength(@Nullable Place place, String propertyName, Set<String> validationFailures) {
        if (place != null) {
            validateLettersLength(place.noPlaceInfo(), propertyName + " - no place info").ifPresent(validationFailures::add);
            validateLettersLength(place.freetextPlace(), propertyName + " - free text place").ifPresent(validationFailures::add);
            if (place.structuredPlace() != null) {
                var sp = place.structuredPlace();
                validateLettersLength(sp.city(), propertyName + " - city").ifPresent(validationFailures::add);
                validateLettersLength(sp.country(), propertyName + " - country").ifPresent(validationFailures::add);
                validateLettersLength(sp.state(), propertyName + " - state").ifPresent(validationFailures::add);
                validateLettersLength(sp.street(), propertyName + " - street").ifPresent(validationFailures::add);
                validateLettersLength(sp.zipCode(), propertyName + " - zip code").ifPresent(validationFailures::add);
            }
        }
    }

    private static Optional<String> validatePlaceOfBirth(@Nullable Place placeOfBirth) {
        if (placeOfBirth == null ||
            (
                placeOfBirth.noPlaceInfo() == null &&
                placeOfBirth.structuredPlace() == null &&
                placeOfBirth.freetextPlace() == null
            )
        ) {
            return Optional.of("Identity data does not contain 'place of birth'");
        }
        return Optional.empty();
    }

    private static Optional<String> validatePlaceOfResidence(@Nullable Place placeOfResidence) {
        if (placeOfResidence == null) {
            return  Optional.of("Identity data does not contain 'place of residence'");
        }
        var structuredPlace = placeOfResidence.structuredPlace();
        if (structuredPlace == null && placeOfResidence.noPlaceInfo() == null) {
            return  Optional.of("Identity data does not contain 'place of residence'");
        } else if (structuredPlace != null) {
            return validateCountryCode(structuredPlace.country(), "place of residence country");
        }
        return Optional.empty();
    }

    private static Optional<String> validateNationality(@Nullable String nationality, @Nullable String documentType) {
        if (!StringUtils.hasText(nationality) && Objects.equals(documentType, DocumentType.ID.name())) {
            return Optional.empty();
        }
        return validateCountryCode(nationality, "nationality");
    }

    private static Optional<String> validateBirthDateString(@Nullable DateOfBirth dateOfBirth) {
        if (dateOfBirth == null) {
            return Optional.of("Identity data does not contain 'date of birth'");
        }
        var dateString = dateOfBirth.dateString();
        if (dateString == null) {
            return Optional.of("Identity data does not contain 'date of birth'");
        }

        try {
            BirthDate.parse(dateString);
        } catch (DateTimeParseException _) {
            return Optional.of("Identity data does not contain a valid 'date of birth'");
        }
        return Optional.empty();
    }

    private static Optional<String> validateCountryCode(@Nullable String countryCode, String propertyName) {
        if (!StringUtils.hasText(countryCode)) {
            return Optional.of("Identity data does not contain '%s'".formatted(propertyName));
        }
        try {
            CountryCodeMapper.convertCountryCode(countryCode);
        } catch (PidServerException _) {
            return Optional.of("Identity data does not contain valid country code for '%s'".formatted(propertyName));
        }
        return Optional.empty();
    }

    private static Optional<String> validateRestrictedId(@Nullable RestrictedId restrictedId) {
        if (restrictedId == null || restrictedId.id() == null) {
            return Optional.of("Identity data does not contain 'restricted id'");
        }
        return Optional.empty();
    }

    private static Optional<String> validateDateOfExpiry(String dateOfExpiry) {
        SimpleDateFormat formatter = new SimpleDateFormat(ISO_DATE_FORMAT);
        try {
            formatter.parse(dateOfExpiry);
            return Optional.empty();
        } catch (ParseException _) {
            return Optional.of("Identity data does not contain a valid 'date of expiry'");
        }
    }
}
