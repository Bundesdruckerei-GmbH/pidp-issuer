/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeParseException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class BirthDateTest {
    private static final LocalDate NOW = LocalDate.now();

    private static Stream<Arguments> validLocalBirthdates() {
        return Stream.of(
            arguments("2012-01-01"),
            arguments("2020-12-00"),
            arguments("2002-00-00")
        );
    }

    private static Stream<Arguments> validBasicBirthdates() {
        return Stream.of(
            arguments("20120101"),
            arguments("20201200"),
            arguments("20020000"),
            arguments("201201  "),
            arguments("202001"),
            arguments("2012    "),
            arguments("2016  "),
            arguments("2020")
        );
    }

    private static Stream<Arguments> invalidBirthdates() {
        return Stream.of(
            arguments("0000-00-00"),
            arguments("2012-00-31"),
            arguments("2012-01-0"),
            arguments("2020-12-ab"),
            arguments(" 200-20-00"),
            arguments("2020-01-02.1"),
            arguments("2020-13-11"),
            arguments("2020-02-31"),
            arguments("")
        );
    }

    @ParameterizedTest
    @MethodSource("validLocalBirthdates")
    void processValidBirthdate(String birthdate) {
        assertEquals(birthdate, new BirthDate(birthdate).toIsoDateString());
    }

    @ParameterizedTest
    @MethodSource("invalidBirthdates")
    void processInvalidBirthdate(String birthString) {
        assertThrows(RuntimeException.class, () -> new BirthDate(birthString));
    }

    @ParameterizedTest
    @MethodSource("validBasicBirthdates")
    void parseWithValidArgs(String birthdate) {
        assertDoesNotThrow(() -> BirthDate.parse(birthdate.replace("-", "")));
    }

    @ParameterizedTest
    @MethodSource("invalidBirthdates")
    void parseWithInvalidArgs(String birthdate) {
        var bd = birthdate.replace("-", "");
        assertThrows(DateTimeParseException.class, () -> BirthDate.parse(bd));
    }

    private static Stream<Arguments> ageArguments() {
        return Stream.of(
            arguments("2012-01-01", LocalDate.of(2012, 1, 1)),
            arguments("2020-12-00", LocalDate.of(2020, 12, 31)),
            arguments("2002-00-00", LocalDate.of(2002, 12, 31))
        );
    }

    @ParameterizedTest
    @MethodSource("ageArguments")
    void processAgeCalculation(String birthString, LocalDate dateForAge) {
        var birthdate = new BirthDate(birthString);
        assertEquals(Period.between(dateForAge, NOW).getYears(), birthdate.getAgeInYears());
    }

    private static Stream<Arguments> validSanitizedBirthDates() {
        return Stream.of(
            arguments("2012-01-01", "2012-01-01"),
            arguments("2020-03-00", "2020-03-31"),
            arguments("2002-00-00", "2002-12-31"),
            arguments("2026-02-00", "2026-02-28"),
            arguments("2027-02-00", "2027-02-28"),
            arguments("2028-02-00", "2028-02-29")
        );
    }

    @ParameterizedTest
    @MethodSource("validSanitizedBirthDates")
    void processSanitizedBirthDate(String birthdate, String expectedSanitized) {
        assertEquals(expectedSanitized, new BirthDate(birthdate).toSanitizedIsoDateString());
    }
}
