/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.policy;

import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.base.identitydata.StructuredPlace;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.assertj.core.api.StringAssert;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;
import java.util.stream.Stream;

import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static org.assertj.core.api.Assertions.assertThat;


class PidIdentityDataValidatorTest {

    @ParameterizedTest
    @EnumSource(value = DocumentType.class)
    void testValidationValidDocumentType(DocumentType documentType) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomDocumentType(documentType.name()));
        assertThat(issuanceDecision).isInstanceOf(ValidIssuanceDecision.class);
    }

    private static Stream<Arguments> invalidDocumentTypes() {
        return Stream.of(
            Arguments.of(null, "Identity data: Document type must not be null"),
            Arguments.of("", "Identity data: Document type  is not valid"),
            Arguments.of(" ", "Identity data: Document type   is not valid"),
            Arguments.of("AB", "Identity data: Document type AB is not valid")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidDocumentTypes")
    void testValidationInvalidDocumentType(String documentType, String expectedError) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomDocumentType(documentType));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of(expectedError));
    }

    @ParameterizedTest
    @ValueSource(strings = {"19900101", "20501231"})
    void testValidationValidDateOfBirth(String dateOfBithString) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomDateOfBirthString(dateOfBithString));
        assertThat(issuanceDecision).isInstanceOf(ValidIssuanceDecision.class);
    }

    private static Stream<Arguments> invalidDateOfBirth() {
        return Stream.of(
            Arguments.of(null, "Identity data does not contain 'date of birth'"),
            Arguments.of("", "Identity data does not contain a valid 'date of birth'"),
            Arguments.of(" ", "Identity data does not contain a valid 'date of birth'"),
            Arguments.of("Invalid date", "Identity data does not contain a valid 'date of birth'"),
            Arguments.of("1990-01-01", "Identity data does not contain a valid 'date of birth'"),
            Arguments.of("199912xx", "Identity data does not contain a valid 'date of birth'"),
            Arguments.of("1999  01", "Identity data does not contain a valid 'date of birth'"),
            Arguments.of("19990230", "Identity data does not contain a valid 'date of birth'")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidDateOfBirth")
    void testValidationInvalidDateOfBirth(String dateOfBirthString, String expectedError) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomDateOfBirthString(dateOfBirthString));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of(expectedError));
    }

    private static Stream<Arguments> validPlaceOfBirth() {
        return Stream.of(
            Arguments.of(new Place(new StructuredPlace(null, null, null, null, null), null, null)),
            Arguments.of(new Place(null, "freeText", null)),
            Arguments.of(new Place(null, null, "noPlaceInfo"))
        );
    }

    @ParameterizedTest
    @MethodSource("validPlaceOfBirth")
    void testValidationValidPlaceOfBirth(Place placeOfBirth) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomPlaceOfBirth(placeOfBirth));
        assertThat(issuanceDecision).isInstanceOf(ValidIssuanceDecision.class);
    }


    private static Stream<Arguments> invalidPlaceOfBirth() {
        return Stream.of(
            Arguments.of(new Place(null, null, null))
        );
    }

    @ParameterizedTest
    @NullSource
    @MethodSource("invalidPlaceOfBirth")
    void testValidationInvalidPlaceOfBirth(Place placeOfBirth) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomPlaceOfBirth(placeOfBirth));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of("Identity data does not contain 'place of birth'"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"D", "USA", "ESP", "ZWE"})
    void testValidationValidNationality(String nationality) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomNationality(nationality));
        assertThat(issuanceDecision).isInstanceOf(ValidIssuanceDecision.class);
    }

    private static Stream<Arguments> invalidNationality() {
        return Stream.of(
            Arguments.of("AAA", "Identity data does not contain valid country code for 'nationality'"),
            Arguments.of("AAAA", "Identity data does not contain valid country code for 'nationality'")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidNationality")
    void testValidationInvalidNationality(String nationality, String expectedError) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomNationality(nationality));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of(expectedError));
    }

    @ParameterizedTest
    @EnumSource(value = DocumentType.class, names = {"ID"}, mode = EnumSource.Mode.EXCLUDE)
    void testValidationInvalidNationalityWhenNationalityEmptyAndDocumentTypeNotID(DocumentType documentType) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomNationalityNull(documentType.name()));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of("Identity data does not contain 'nationality'"));
    }


    private static Stream<Arguments> validPlaceOfResidence() {
        return Stream.of(
            Arguments.of(new Place(new StructuredPlace(null, null, "D", null, null), null, null)),
            Arguments.of(new Place(new StructuredPlace(null, null, "USA", null, null), null, null)),
            Arguments.of(new Place(null, null, "noPlaceInfo"))
        );
    }

    @ParameterizedTest
    @MethodSource("validPlaceOfResidence")
    void testValidationValidPlaceOfResidence(Place placeOfResidence) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomPlaceOfResidence(placeOfResidence));
        assertThat(issuanceDecision).isInstanceOf(ValidIssuanceDecision.class);
    }


    private static Stream<Arguments> invalidPlaceOfResidence() {
        return Stream.of(
            Arguments.of(null, "Identity data does not contain 'place of residence'"),
            Arguments.of(new Place(null, null, null), "Identity data does not contain 'place of residence'"),
            Arguments.of(new Place(null, "freeText", null), "Identity data does not contain 'place of residence'"),
            Arguments.of(new Place(new StructuredPlace(null, null, null, null, null), null, null), "Identity data does not contain 'place of residence country'"),
            Arguments.of(new Place(new StructuredPlace(null, null, "AAA", null, null), null, null), "Identity data does not contain valid country code for 'place of residence country'")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidPlaceOfResidence")
    void testValidationInvalidPlaceOfResidence(Place placeOfResidence, String expectedError) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomPlaceOfResidence(placeOfResidence));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of(expectedError));
    }

    @Test
    void testValidationValidRestrictedId() {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomRestrictedId(new RestrictedId("restrictedId")));
        assertThat(issuanceDecision)
            .isInstanceOf(ValidIssuanceDecision.class);
    }

    private static Stream<Arguments> invalidRestrictedIds() {
        return Stream.of(
            Arguments.of(new RestrictedId(null))
        );
    }

    @ParameterizedTest
    @NullSource
    @MethodSource("invalidRestrictedIds")
    void testValidationInvalidRestrictedId(RestrictedId restrictedId) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataCustomRestrictedId(restrictedId));
        assertThat(issuanceDecision)
            .isInstanceOf(InvalidIssuanceDecision.class)
            .hasFieldOrPropertyWithValue("reasons", Set.of("Identity data does not contain 'restricted id'"));
    }

    @Test
    void testLettersLength() {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataStringLength(TOO_LARGE_STRING));
        assertThat(issuanceDecision).isInstanceOf(InvalidIssuanceDecision.class).extracting("reasons")
            .asInstanceOf(InstanceOfAssertFactories.set(StringAssert.class)).hasSize(18);
        issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(getIdentityDataStringLength(LARGE_STRING));
        assertThat(issuanceDecision).isInstanceOf(ValidIssuanceDecision.class);
    }

    private static IdentityData getIdentityDataCustomDocumentType(String documentType) {
        assert TEST_IDENTITY_DATA.dateOfBirth() != null;
        return getIdentityDataCustom(documentType, TEST_IDENTITY_DATA.dateOfBirth().dateString(), TEST_IDENTITY_DATA.placeOfBirth(),
            TEST_IDENTITY_DATA.nationality(), TEST_IDENTITY_DATA.placeOfResidence(), TEST_IDENTITY_DATA.restrictedId());
    }

    private static IdentityData getIdentityDataCustomDateOfBirthString(String dateOfBirthString) {
        return getIdentityDataCustom(TEST_IDENTITY_DATA.documentType(), dateOfBirthString, TEST_IDENTITY_DATA.placeOfBirth(),
            TEST_IDENTITY_DATA.nationality(), TEST_IDENTITY_DATA.placeOfResidence(), TEST_IDENTITY_DATA.restrictedId());
    }

    private static IdentityData getIdentityDataCustomPlaceOfBirth(Place placeOfBirth) {
        assert TEST_IDENTITY_DATA.dateOfBirth() != null;
        return getIdentityDataCustom(TEST_IDENTITY_DATA.documentType(), TEST_IDENTITY_DATA.dateOfBirth().dateString(), placeOfBirth,
            TEST_IDENTITY_DATA.nationality(), TEST_IDENTITY_DATA.placeOfResidence(), TEST_IDENTITY_DATA.restrictedId());
    }

    private static IdentityData getIdentityDataCustomNationality(String nationality) {
        assert TEST_IDENTITY_DATA.dateOfBirth() != null;
        return getIdentityDataCustom(TEST_IDENTITY_DATA.documentType(), TEST_IDENTITY_DATA.dateOfBirth().dateString(),
            TEST_IDENTITY_DATA.placeOfBirth(), nationality, TEST_IDENTITY_DATA.placeOfResidence(), TEST_IDENTITY_DATA.restrictedId());
    }

    private static IdentityData getIdentityDataCustomNationalityNull(String documentType) {
        assert TEST_IDENTITY_DATA.dateOfBirth() != null;
        return getIdentityDataCustom(documentType, TEST_IDENTITY_DATA.dateOfBirth().dateString(),
            TEST_IDENTITY_DATA.placeOfBirth(), null, TEST_IDENTITY_DATA.placeOfResidence(), TEST_IDENTITY_DATA.restrictedId());
    }

    private static IdentityData getIdentityDataCustomPlaceOfResidence(Place placeOfResidence) {
        assert TEST_IDENTITY_DATA.dateOfBirth() != null;
        return getIdentityDataCustom(TEST_IDENTITY_DATA.documentType(), TEST_IDENTITY_DATA.dateOfBirth().dateString(),
            TEST_IDENTITY_DATA.placeOfBirth(), TEST_IDENTITY_DATA.nationality(), placeOfResidence, TEST_IDENTITY_DATA.restrictedId());
    }

    private static IdentityData getIdentityDataCustomRestrictedId(RestrictedId restrictedId) {
        assert TEST_IDENTITY_DATA.dateOfBirth() != null;
        return getIdentityDataCustom(TEST_IDENTITY_DATA.documentType(), TEST_IDENTITY_DATA.dateOfBirth().dateString(),
            TEST_IDENTITY_DATA.placeOfBirth(), TEST_IDENTITY_DATA.nationality(), TEST_IDENTITY_DATA.placeOfResidence(), restrictedId);
    }

    private static IdentityData getIdentityDataCustom(@Nullable String documentType,
                                                      @Nullable String dateOfBirthString,
                                                      @Nullable Place placeOfBirth,
                                                      @Nullable String nationality,
                                                      @Nullable Place placeOfResidence,
                                                      @Nullable RestrictedId restrictedId) {
        return new IdentityData(
            documentType,
            TEST_IDENTITY_DATA.issuingState(),
            TEST_IDENTITY_DATA.dateOfExpiry(),
            TEST_IDENTITY_DATA.givenNames(),
            TEST_IDENTITY_DATA.familyNames(),
            TEST_IDENTITY_DATA.artisticName(),
            TEST_IDENTITY_DATA.academicTitle(),
            new DateOfBirth(null, dateOfBirthString),
            placeOfBirth,
            nationality,
            TEST_IDENTITY_DATA.birthName(),
            placeOfResidence,
            restrictedId);
    }

    private static final String LARGE_STRING = "𝕒𝕓𝕔".repeat(25) + "_"; // this is not normal "abc"! Length = 25 * 6 + 1, chars = 25 * 3 + 1!!
    private static final String TOO_LARGE_STRING = "_123456789".repeat(15) + "_"; // Length = chars = 15 * 10 + 1

    private static IdentityData getIdentityDataStringLength(String str) {
        return new IdentityData(
            TEST_IDENTITY_DATA.documentType(),
            TEST_IDENTITY_DATA.issuingState(),
            TEST_IDENTITY_DATA.dateOfExpiry(),
            str,
            str,
            str,
            str,
            TEST_IDENTITY_DATA.dateOfBirth(),
            new Place(new StructuredPlace(str, str, str, str, str), str, str),
            "D",
            str,
            new Place(new StructuredPlace(str, str, "D", str, str), str, str),
            new RestrictedId("RVJJS0E=")
        );

    }
}
