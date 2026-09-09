/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.Month;
import java.time.Period;
import java.time.Year;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The BirthDate is a date for which the day of the month or month and the day of the month may be unknown.
 *
 */
@NullMarked
public final class BirthDate {
    private static final String ERROR_MSG = "Illegal birthdate";

    // we only accept birthdates on or behind 1000-01-01
    private static final Pattern BIRTHDATE_BASIC_PATTERN = Pattern.compile("^[1-9]((\\d{7})|(\\d{5} {0,2})|(\\d{3} {0,4}))$");
    private static final Pattern BIRTHDATE_ISO_PATTERN = Pattern.compile("^[1-9]\\d{3}-\\d{2}-\\d{2}$");

    private static final ZoneId AGE_REF_ZONE_ID = ZoneId.of("Europe/Berlin");

    private final TemporalAccessor birthday;

    private BirthDate(TemporalAccessor birthday) {
        this.birthday = birthday;
    }

    /**
     * The expected format is {@link java.time.format.DateTimeFormatter#ISO_LOCAL_DATE ISO_LOCAL_DATE} = ‘yyyy-MM-dd’,
     * where the year part must always represent a valid year >= 1000.
     * The day or month and day may be unknown. Then they must be represented as ‘00’.<br>
     * For example: '2026-02-17', '2026-02-00', or '2026-00-00'.
     *
     * @param localBirthdate the birthdate as String
     */
    @JsonCreator
    public BirthDate(String localBirthdate) {
        if (!BIRTHDATE_ISO_PATTERN.matcher(localBirthdate).matches()) {
            throw new IllegalArgumentException(ERROR_MSG);
        }
        this.birthday = validate(localBirthdate.replace("-", ""));
    }

    /**
     * The expected format here is {@link java.time.format.DateTimeFormatter#BASIC_ISO_DATE BASIC_ISO_DATE} = ‘yyyyMMdd’,
     * where the year part must always represent a valid year >= 1000.
     * The day or month and day may be unknown. Then they can be represented as ‘00’
     * or as '  ' (two spaces) or can be omitted.<br>
     * For example: '20260217', '202602  ', '202602', '2026    ' or '2026'.
     *
     * @param basicBirthdate the birthdate as String
     */
    public static BirthDate parse(String basicBirthdate) {
        if (!BIRTHDATE_BASIC_PATTERN.matcher(basicBirthdate).matches()) {
            throw new DateTimeParseException(ERROR_MSG, basicBirthdate, 0);
        }
        return new BirthDate(validate(normalizeBirthdateString(basicBirthdate)));
    }

    private static String normalizeBirthdateString(String basicBirthdate) {
        var bd = basicBirthdate.stripTrailing();
        var len = bd.length();
        return bd + "0000".substring(0, 8 - len);
    }

    private static TemporalAccessor validate(String birthdate) {
        final TemporalAccessor birthday;
        int parsePosition = 0;
        try {
            int year = Integer.parseInt(birthdate.substring(0, 4));
            parsePosition = 4;
            int month = Integer.parseInt(birthdate.substring(4, 6));
            parsePosition = 6;
            int day = Integer.parseInt(birthdate.substring(6, 8));
            parsePosition = 0;
            if (day != 0) {
                birthday = LocalDate.of(year, month, day);
            } else if (month != 0) {
                birthday = YearMonth.of(year, month);
            } else {
                birthday = Year.of(year);
            }
        } catch (NumberFormatException | DateTimeException e) {
            throw new DateTimeParseException(ERROR_MSG, birthdate, parsePosition, e);
        }
        return birthday;
    }

    @JsonValue
    public String toIsoDateString() {
        int day = birthday.isSupported(ChronoField.DAY_OF_MONTH) ? birthday.get(ChronoField.DAY_OF_MONTH) : 0;
        int month = birthday.isSupported(ChronoField.MONTH_OF_YEAR) ? birthday.get(ChronoField.MONTH_OF_YEAR) : 0;
        int year = birthday.get(ChronoField.YEAR);

        return "%04d-%02d-%02d".formatted(year, month, day);
    }

    /**
     * Returns an ISO‑date string where unknown month or day are replaced by the maximum possible values.
     * For an unknown month, the last month of year is used; for an unknown day, the last day of the month
     * (taking leap years into account) is used.
     *
     * @return sanitized ISO‑date string
     */
    public String toSanitizedIsoDateString() {
        int year = birthday.get(ChronoField.YEAR);
        int month = birthday.isSupported(ChronoField.MONTH_OF_YEAR) ? birthday.get(ChronoField.MONTH_OF_YEAR) : 12;
        int day;
        if (birthday.isSupported(ChronoField.DAY_OF_MONTH)) {
            day = birthday.get(ChronoField.DAY_OF_MONTH);
        } else {
            YearMonth ym = YearMonth.of(year, month);
            day = ym.lengthOfMonth();
        }
        return "%04d-%02d-%02d".formatted(year, month, day);
    }

    /**
     * Calculates age in years even if the day or day and month are unknown.
     * If the month is unknown, the last month of the year (= december) is assumed.
     * If the day is unknown, the last day of the month is used for the calculation.
     *
     * @return the calculated age
     */
    @JsonIgnore
    public int getAgeInYears() {
        final LocalDate now = LocalDate.now(AGE_REF_ZONE_ID);
        final LocalDate bd;
        if (birthday.isSupported(ChronoField.DAY_OF_MONTH)) {
            bd = LocalDate.from(birthday);
        } else if (birthday.isSupported(ChronoField.MONTH_OF_YEAR)) {
            bd = YearMonth.from(birthday).atEndOfMonth();
        } else {
            bd = Year.from(birthday).atMonth(Month.DECEMBER).atEndOfMonth();
        }
        return Period.between(bd, now).getYears();
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        BirthDate birthDate = (BirthDate) o;
        return Objects.equals(birthday, birthDate.birthday);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(birthday);
    }
}
