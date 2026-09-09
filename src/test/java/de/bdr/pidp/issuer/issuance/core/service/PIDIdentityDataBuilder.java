/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import de.bdr.pidp.issuer.base.BirthDate;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

@NullMarked
public class PIDIdentityDataBuilder {
    private String documentType = DocumentType.ID.name();
    private String dateOfExpiry = "2046-01-23";
    @Nullable private String givenNames = "ERIKA";
    @Nullable private String familyNames = "MUSTERMANN";
    @Nullable private String artisticName = "MUSTERFRAU";
    @Nullable private String academicTitle = "DR";
    private BirthDate dateOfBirth = new BirthDate("1964-08-12");
    private PlaceOfBirth placeOfBirth = new PlaceOfBirthBuilder().build();
    private String nationality = "D";
    @Nullable private String birthName = "GABLER";
    private PlaceOfResidence placeOfResidence = new PlaceBuilder().build();
    private String restrictedId = "RVJJS0E=";

    public PIDIdentityDataBuilder documentType(String documentType) {
        this.documentType = documentType;
        return this;
    }

    public PIDIdentityDataBuilder dateOfExpiry(String dateOfExpiry) {
        this.dateOfExpiry = dateOfExpiry;
        return this;
    }

    public PIDIdentityDataBuilder givenNames(@Nullable String givenNames) {
        this.givenNames = givenNames;
        return this;
    }

    public PIDIdentityDataBuilder familyNames(@Nullable String familyNames) {
        this.familyNames = familyNames;
        return this;
    }

    public PIDIdentityDataBuilder artisticName(@Nullable String artisticName) {
        this.artisticName = artisticName;
        return this;
    }

    public PIDIdentityDataBuilder academicTitle(@Nullable String academicTitle) {
        this.academicTitle = academicTitle;
        return this;
    }

    public PIDIdentityDataBuilder dateOfBirth(BirthDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
        return this;
    }

    public PIDIdentityDataBuilder placeOfBirth(PlaceOfBirth placeOfBirth) {
        this.placeOfBirth = placeOfBirth;
        return this;
    }

    public PIDIdentityDataBuilder nationality(String nationality) {
        this.nationality = nationality;
        return this;
    }

    public PIDIdentityDataBuilder birthName(@Nullable String birthName) {
        this.birthName = birthName;
        return this;
    }

    public PIDIdentityDataBuilder placeOfResidence(PlaceOfResidence placeOfResidence) {
        this.placeOfResidence = placeOfResidence;
        return this;
    }

    public PIDIdentityDataBuilder restrictedId(String restrictedId) {
        this.restrictedId = restrictedId;
        return this;
    }

    public PIDIdentityData build() {
        return new PIDIdentityData(
            documentType,
            dateOfExpiry,
            givenNames,
            familyNames,
            artisticName,
            academicTitle,
            dateOfBirth,
            placeOfBirth,
            nationality,
            birthName,
            placeOfResidence,
            restrictedId
        );
    }

    static class PlaceOfBirthBuilder {
        private String locality = "BERLIN";

        public PlaceOfBirthBuilder locality(String locality) {
            this.locality = locality;
            return this;
        }

        public PlaceOfBirth build() {
            return new Locality(locality);
        }

        public static PlaceOfBirth noPlaceInfo() {
            return new NoPlaceInfo();
        }
    }

    static class PlaceBuilder {
        @Nullable private String street = "HEIDESTRASSE 17";
        @Nullable private String city = "KÖLN";
        private String country = "D";
        @Nullable private String state = "NRW";
        @Nullable private String zipCode = "51147";

        public PlaceBuilder street(@Nullable String street) {
            this.street = street;
            return this;
        }

        public PlaceBuilder city(@Nullable String city) {
            this.city = city;
            return this;
        }

        public PlaceBuilder country(String country) {
            this.country = country;
            return this;
        }

        public PlaceBuilder state(@Nullable String state) {
            this.state = state;
            return this;
        }

        public PlaceBuilder zipCode(@Nullable String zipCode) {
            this.zipCode = zipCode;
            return this;
        }

        public PlaceOfResidence build() {
            return new StructuredPlace(street, city, country, state, zipCode);
        }

        public static PlaceOfResidence noPlaceInfo() {
            return new NoPlaceInfo();
        }
    }
}
