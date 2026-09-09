/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance;

import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.base.identitydata.StructuredPlace;
import org.jspecify.annotations.Nullable;

public abstract class IdentityDataBase {

    public static IdentityData getIdentityData() {
        return getIdentityDataOfNationality("DE");
    }

    public static IdentityData getIdentityDataOfNationality(String countryCode) {
        return new IdentityData(
            "ID",
            "DE",
            "2099-12-31",
            "givenName",
            "familyName",
            "artisticName",
            "academicTitle",
            new DateOfBirth("2000-01-01", "20000101"),
            new Place(null, "placeOfBirth", null),
            countryCode,
            "birthFamilyName",
            new Place(new StructuredPlace("streetAddress", "locality", "DE", "region", "12345"), null, null),
            new RestrictedId("pseudonym")
        );
    }

    public static IdentityData getIdentityDataOfBirthPlaceCountry(String countryCode) {
        return new IdentityData(
            "ID",
            "DE",
            "2099-12-31",
            "givenName",
            "familyName",
            null,
            null,
            new DateOfBirth("2000-01-01", "20000101"),
            new Place(new StructuredPlace("streetAddress", "placeOfBirth", countryCode, "region", "12345"), null, null),
            "DE",
            "birthFamilyName",
            new Place(new StructuredPlace("streetAddress", "locality", "DE", "region", "12345"), null, null),
            new RestrictedId("pseudonym")
        );
    }

    public static IdentityData getMinimalIdentityData() {
        return new IdentityData(
            "ID",
            "DE",
            "2099-12-31",
            "givenName",
            "familyName",
            null,
            null,
            new DateOfBirth("2000-01-01", "20000101"),
            new Place(null, null, null),
            "DE",
            null,
            new Place(null, null, "noPlaceInfo"),
            new RestrictedId("pseudonym")
        );
    }

    public static IdentityData getMaximalIdentityData() {
        return new IdentityData(
            "ID",
            "DE",
            "2099-12-31",
            "givenName",
            "familyName",
            "artisticName",
            "academicTitle",
            new DateOfBirth("2000-01-01", "20000101"),
            new Place(null, "placeOfBirth", null),
            "DE",
            "birthFamilyName",
            new Place(new StructuredPlace("streetAddress", "locality", "DE", "region", "12345"), null, null),
            new RestrictedId("pseudonym")
        );
    }

    public static int getNrOfPropertiesOfPlaceNotNull(@Nullable Place place) {
        int nrOfFilledProperties = 0;
        if (place != null) {
            var structuredPlace = place.structuredPlace();
            if (structuredPlace != null) {
                if (structuredPlace.country() != null) {
                    nrOfFilledProperties++;
                }
                if (structuredPlace.state() != null) {
                    nrOfFilledProperties++;
                }
                if (structuredPlace.city() != null) {
                    nrOfFilledProperties++;
                }
                if (structuredPlace.zipCode() != null) {
                    nrOfFilledProperties++;
                }
                if (structuredPlace.street() != null) {
                    nrOfFilledProperties++;
                }
            }
        }
        return nrOfFilledProperties;
    }

    public static int getNrOfPropertiesOfPlaceOfBirthNotNull(Place placeOfBirth) {
        int nrOfFilledProperties = 0;
        if (placeOfBirth != null &&
            (placeOfBirth.freetextPlace() != null ||
                placeOfBirth.noPlaceInfo() != null ||
                (placeOfBirth.structuredPlace() != null && placeOfBirth.structuredPlace().city() != null))
        ) {
            nrOfFilledProperties++;
        }
        return nrOfFilledProperties;
    }
}
