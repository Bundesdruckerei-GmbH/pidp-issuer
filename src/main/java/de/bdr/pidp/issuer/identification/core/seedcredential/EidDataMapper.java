/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.base.identitydata.StructuredPlace;
import de.bdr.pidp.issuer.identification.core.exception.InvalidEidData;
import de.bund.bsi.eid240.GeneralDateType;
import de.bund.bsi.eid240.GeneralPlaceType;
import de.bund.bsi.eid240.PersonalDataType;
import de.bund.bsi.eid240.RestrictedIDType;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.exc.UnrecognizedPropertyException;
import tools.jackson.databind.json.JsonMapper;

import javax.xml.datatype.XMLGregorianCalendar;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@NullMarked
@RequiredArgsConstructor
public class EidDataMapper {
    private static final String ISO_DATE_FORMAT = "yyyy-MM-dd";
    private static final String NAMESPACE_IDENTITY_DATA = "https://pid-provider.bundesdruckerei.de/identity_data";

    // UUID-V7 generator
    private final TimeBasedEpochGenerator uuidGenerator = Generators.timeBasedEpochGenerator();
    private final JsonMapper objectMapper = JsonMapper.builder()
        .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
    private final String audience;

    public IdentityData map(PersonalDataType personalDataType) {
        return new IdentityData(
            personalDataType.getDocumentType(),
            personalDataType.getIssuingState(),
            mapDateOfExpiry(personalDataType.getDateOfExpiry()),
            personalDataType.getGivenNames(),
            personalDataType.getFamilyNames(),
            personalDataType.getArtisticName(),
            personalDataType.getAcademicTitle(),
            mapDateOfBirth(personalDataType.getDateOfBirth()),
            mapPlace(personalDataType.getPlaceOfBirth()),
            personalDataType.getNationality(),
            personalDataType.getBirthName(),
            mapPlace(personalDataType.getPlaceOfResidence()),
            mapRestrictedId(personalDataType.getRestrictedID())
        );
    }

    private static @Nullable DateOfBirth mapDateOfBirth(@Nullable GeneralDateType generalDateType) {
        if (generalDateType != null) {
            return new DateOfBirth(
                mapXmlGregorianCalenderToString(generalDateType.getDateValue()),
                generalDateType.getDateString()
            );
        }
        return null;
    }

    private static @Nullable Place mapPlace(@Nullable GeneralPlaceType personalDataType) {
        if (personalDataType != null) {
            StructuredPlace structuredPlace = personalDataType.getStructuredPlace() != null ?
                new StructuredPlace(
                    personalDataType.getStructuredPlace().getStreet(),
                    personalDataType.getStructuredPlace().getCity(),
                    personalDataType.getStructuredPlace().getCountry(),
                    personalDataType.getStructuredPlace().getState(),
                    personalDataType.getStructuredPlace().getZipCode()
                )
                : null;

            return new Place(
                structuredPlace,
                personalDataType.getFreetextPlace(),
                personalDataType.getNoPlaceInfo()
            );
        }
        return null;
    }

    public JWTClaimsSet map(IdentityData identityData) {
        var now = Instant.now();
        JWTClaimsSet.Builder cb = new JWTClaimsSet.Builder();

        cb.audience(audience);
        cb.subject(identityData.restrictedId() != null ? identityData.restrictedId().id() : null);
        cb.issueTime(new Date(now.toEpochMilli()));
        cb.expirationTime(dateOfExpiryStringToDate(identityData.dateOfExpiry()));

        cb.jwtID(uuidGenerator.generate().toString());

        var identityDataMap = JSONObjectUtils.newJSONObject();

        write(identityDataMap, "document_type", identityData.documentType());
        write(identityDataMap, "issuing_state", identityData.issuingState());
        write(identityDataMap, "date_of_expiry", identityData.dateOfExpiry());
        write(identityDataMap, "given_names", identityData.givenNames());
        write(identityDataMap, "family_names", identityData.familyNames());
        write(identityDataMap, "artistic_name", identityData.artisticName());
        write(identityDataMap, "academic_title", identityData.academicTitle());
        writeBirthdate(identityDataMap, identityData.dateOfBirth());
        writePlace(identityDataMap, "place_of_birth", identityData.placeOfBirth());
        write(identityDataMap, "nationality", identityData.nationality());
        write(identityDataMap, "birth_name", identityData.birthName());
        writePlace(identityDataMap, "place_of_residence", identityData.placeOfResidence());
        writeRestrictedID(identityDataMap, identityData.restrictedId());

        cb.claim(NAMESPACE_IDENTITY_DATA, identityDataMap);
        return cb.build();
    }

    /**
     * @throws ParseException when {@link IdentityData} could not be mapped to
     */
    public IdentityData map(JWTClaimsSet claimsSet) throws ParseException {
        var namespace = claimsSet.getJSONObjectClaim(NAMESPACE_IDENTITY_DATA);
        if (namespace == null) {
            throw new ParseException("Namespace not found", 0);
        }
        try {
            return objectMapper.convertValue(namespace, IdentityData.class);
        } catch (UnrecognizedPropertyException e) {
            throw new ParseException(e.getMessage(), 0);
        }
    }

    private static void writePlace(Map<String, Object> json, String claimName, @Nullable Place place) {
        if (place != null) {
            var placeJson = JSONObjectUtils.newJSONObject();
            var structuredPlace = place.structuredPlace();
            if (structuredPlace != null) {
                var structuredPlaceJson = JSONObjectUtils.newJSONObject();

                write(structuredPlaceJson, "street", structuredPlace.street());
                write(structuredPlaceJson, "city", structuredPlace.city());
                write(structuredPlaceJson, "country", structuredPlace.country());
                write(structuredPlaceJson, "state", structuredPlace.state());
                write(structuredPlaceJson, "zip_code", structuredPlace.zipCode());

                placeJson.put("structured_place", structuredPlaceJson);
            }
            write(placeJson, "freetext_place", place.freetextPlace());
            write(placeJson, "no_place_info", place.noPlaceInfo());

            json.put(claimName, placeJson);
        }
    }

    private static void writeBirthdate(Map<String, Object> json, @Nullable DateOfBirth birthdate) {
        if (birthdate != null) {
            var birthdateJson = JSONObjectUtils.newJSONObject();
            write(birthdateJson, "date_string", birthdate.dateString());
            write(birthdateJson, "date_value", birthdate.dateValue());
            json.put("date_of_birth", birthdateJson);
        }
    }

    private static void writeRestrictedID(Map<String, Object> json, @Nullable RestrictedId restrictedID) {
        if (restrictedID != null) {
            var restrictedIdJson = JSONObjectUtils.newJSONObject();
            write(restrictedIdJson, "id", restrictedID.id());

            json.put("restricted_id", restrictedIdJson);
        }
    }

    private static void write(Map<String, Object> json, String claimName, @Nullable String value) {
        if (value != null) {
            json.put(claimName, value);
        }
    }

    private static @Nullable RestrictedId mapRestrictedId(@Nullable RestrictedIDType restrictedID) {
        if (restrictedID != null && restrictedID.getID() != null) {
            return new RestrictedId(Base64.getUrlEncoder().encodeToString(restrictedID.getID()));
        } else if (restrictedID != null && restrictedID.getID() == null) {
            return new RestrictedId(null);
        }
        return null;
    }

    private static String mapDateOfExpiry(XMLGregorianCalendar xcal) {
        String dateOfExpiryString = mapXmlGregorianCalenderToString(xcal);
        if (dateOfExpiryString == null) {
            throw new InvalidEidData();
        }
        return dateOfExpiryString;
    }

    private static @Nullable String mapXmlGregorianCalenderToString(@Nullable XMLGregorianCalendar xcal) {
        if (xcal == null) {
            return null;
        }
        Date d = xcal.toGregorianCalendar().getTime();
        SimpleDateFormat sdf = new SimpleDateFormat(ISO_DATE_FORMAT);
        return sdf.format(d);
    }

    private static Date dateOfExpiryStringToDate(String dateAsString) {
        SimpleDateFormat formatter = new SimpleDateFormat(ISO_DATE_FORMAT);
        try {
            return formatter.parse(dateAsString);
        } catch (ParseException _) {
            throw new InvalidEidData();
        }
    }
}
