/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import de.bdr.pidp.issuer.base.BirthDate;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

@NullMarked
public record PIDIdentityData(
    String documentType,
    String dateOfExpiry,
    @Nullable String givenNames,
    @Nullable String familyNames,
    @Nullable String artisticName,
    @Nullable String academicTitle,
    BirthDate dateOfBirth,
    PlaceOfBirth placeOfBirth,
    String nationality,
    @Nullable String birthName,
    PlaceOfResidence placeOfResidence,
    String restrictedId
) {

    public static PIDIdentityData fromIdentityData(IdentityData data) {
        return new PIDIdentityData(
            Objects.requireNonNull(data.documentType()),
            data.dateOfExpiry(),
            data.givenNames(),
            data.familyNames(),
            data.artisticName(),
            data.academicTitle(),
            BirthDate.parse(Objects.requireNonNull(Objects.requireNonNull(data.dateOfBirth()).dateString())),
            mapPlaceOfBirth(Objects.requireNonNull(data.placeOfBirth())),
            Objects.requireNonNull(data.nationality()),
            data.birthName(),
            mapPlaceOfResidence(Objects.requireNonNull(data.placeOfResidence())),
            Objects.requireNonNull(Objects.requireNonNull(data.restrictedId()).id())
        );
    }

    private static PlaceOfBirth mapPlaceOfBirth(Place place) {
        if (place.structuredPlace() != null && place.structuredPlace().city() != null) {
            return new Locality(Objects.requireNonNull(place.structuredPlace().city()));
        }
        if (place.freetextPlace() != null) {
            return new Locality(Objects.requireNonNull(place.freetextPlace()));
        }
        return new NoPlaceInfo();
    }

    private static PlaceOfResidence mapPlaceOfResidence(Place place) {
        var structuredPlace = place.structuredPlace();
        if (structuredPlace != null) {
            return new StructuredPlace(
                structuredPlace.street(),
                structuredPlace.city(),
                Objects.requireNonNull(structuredPlace.country()),
                structuredPlace.state(),
                structuredPlace.zipCode()
            );
        }
        Objects.requireNonNull(place.noPlaceInfo());
        return new NoPlaceInfo();
    }
}

sealed interface PlaceOfBirth permits Locality, NoPlaceInfo {
}

sealed interface PlaceOfResidence permits StructuredPlace, NoPlaceInfo {
}

@NullMarked
record Locality(
    String locality
) implements PlaceOfBirth {
}

@NullMarked
record NoPlaceInfo() implements PlaceOfBirth, PlaceOfResidence {
}

@NullMarked
record StructuredPlace(
    @Nullable String street,
    @Nullable String city,
    String country,
    @Nullable String state,
    @Nullable String zipCode
) implements PlaceOfResidence {
}

