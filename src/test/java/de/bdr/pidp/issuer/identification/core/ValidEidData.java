/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bund.bsi.eid240.GeneralDateType;
import de.bund.bsi.eid240.GeneralPlaceType;
import de.bund.bsi.eid240.PersonalDataType;
import de.bund.bsi.eid240.RestrictedIDType;
import org.jspecify.annotations.NonNull;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import java.time.LocalDate;
import java.util.Objects;

import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA_2;

public class ValidEidData {

    private static final DatatypeFactory XML_DATATYPE_FACTORY = DatatypeFactory.newDefaultInstance();

    public static final PersonalDataType TEST_PERSONAL_DATA_TYPE = mapToPersonalDataType(TEST_IDENTITY_DATA);

    public static final PersonalDataType TEST_PERSONAL_DATA_TYPE_2 = mapToPersonalDataType(TEST_IDENTITY_DATA_2);

    public static PersonalDataType mapToPersonalDataType(IdentityData identityData) {
        PersonalDataType result = new PersonalDataType();
        RestrictedIDType pseudonym = new RestrictedIDType();
        byte[] idData = Objects.requireNonNull(identityData.givenNames()).getBytes();
        pseudonym.setID(idData);
        result.setRestrictedID(pseudonym);
        result.setGivenNames(identityData.givenNames());
        result.setFamilyNames(identityData.familyNames());
        result.setBirthName(identityData.birthName());
        result.setArtisticName(identityData.artisticName());
        result.setAcademicTitle(identityData.academicTitle());
        result.setNationality(identityData.nationality());
        result.setDocumentType(identityData.documentType());
        result.setPlaceOfBirth(getGeneralPlaceType(identityData.placeOfBirth()));

        result.setDateOfBirth(getGeneralDateType(identityData.dateOfBirth()));

        result.setPlaceOfResidence(getGeneralPlaceType(identityData.placeOfResidence()));

        LocalDate parsed = LocalDate.parse(identityData.dateOfExpiry());
        var dateOfExpiry = XML_DATATYPE_FACTORY.newXMLGregorianCalendarDate
            (parsed.getYear(), parsed.getMonthValue(), parsed.getDayOfMonth(), DatatypeConstants.FIELD_UNDEFINED);
        result.setDateOfExpiry(dateOfExpiry);

        return result;
    }

    private static GeneralDateType getGeneralDateType(DateOfBirth dateOfBirth) {
        if (dateOfBirth != null) {
            GeneralDateType generalDateType = new GeneralDateType();

            if (dateOfBirth.dateString() != null) {
                generalDateType.setDateString(dateOfBirth.dateString());
            }
            if (dateOfBirth.dateValue() != null) {
                try {
                    generalDateType.setDateValue(DatatypeFactory.newInstance().newXMLGregorianCalendar(dateOfBirth.dateValue()));
                } catch (DatatypeConfigurationException _) {
                    // Do nothing
                }
            }
            return generalDateType;
        }
        return null;
    }

    private static @NonNull GeneralPlaceType getGeneralPlaceType(Place place) {
        GeneralPlaceType generalPlaceType = new GeneralPlaceType();
        if (place != null) {
            if (place.structuredPlace() != null) {
                var p = new de.bund.bsi.eid240.PlaceType();
                p.setStreet(place.structuredPlace().street());
                p.setZipCode(place.structuredPlace().zipCode());
                p.setCity(place.structuredPlace().city());
                p.setState(place.structuredPlace().state());
                p.setCountry(place.structuredPlace().country());
                generalPlaceType.setStructuredPlace(p);
            }
            generalPlaceType.setFreetextPlace(place.freetextPlace());
            generalPlaceType.setNoPlaceInfo(place.noPlaceInfo());
            return generalPlaceType;
        } else {
            return generalPlaceType;
        }
    }
}
