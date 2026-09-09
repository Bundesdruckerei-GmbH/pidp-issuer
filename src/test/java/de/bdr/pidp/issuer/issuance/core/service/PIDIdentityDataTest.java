/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import de.bdr.pidp.issuer.base.BirthDate;
import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

class PIDIdentityDataTest {

    @Test
    void fromIdentityData_WithCompleteData_ShouldMapCorrectly() {
        // Arrange
        IdentityData identityData = new IdentityData(
            "ID",
            "DE",
            "2030-12-31",
            "Max",
            "Mustermann",
            "Künstler",
            "Dr.",
            new DateOfBirth("1980-01-15", "19800115"),
            new Place(
                new de.bdr.pidp.issuer.base.identitydata.StructuredPlace("Musterstraße 1", "Berlin", "DE", "Berlin", "10115"),
                null,
                null
            ),
            "DE",
            "Max Mustermann",
            new Place(
                new de.bdr.pidp.issuer.base.identitydata.StructuredPlace("Hauptstraße 42", "München", "DE", "Bayern", "80331"),
                null,
                null
            ),
            new RestrictedId("123456789")
        );

        // Act
        PIDIdentityData result = PIDIdentityData.fromIdentityData(identityData);

        // Assert
        assertThat(result.documentType()).isEqualTo("ID");
        assertThat(result.dateOfExpiry()).isEqualTo("2030-12-31");
        assertThat(result.givenNames()).isEqualTo("Max");
        assertThat(result.familyNames()).isEqualTo("Mustermann");
        assertThat(result.artisticName()).isEqualTo("Künstler");
        assertThat(result.academicTitle()).isEqualTo("Dr.");
        assertThat(result.dateOfBirth()).isEqualTo(new BirthDate("1980-01-15"));
        assertThat(result.placeOfBirth()).isInstanceOf(Locality.class);
        assertThat(result.placeOfBirth())
            .asInstanceOf(type(Locality.class))
            .extracting(Locality::locality)
            .isEqualTo("Berlin");
        assertThat(result.nationality()).isEqualTo("DE");
        assertThat(result.birthName()).isEqualTo("Max Mustermann");
        assertThat(result.placeOfResidence()).isInstanceOf(StructuredPlace.class);
        StructuredPlace residence = (StructuredPlace) result.placeOfResidence();
        assertThat(residence.street()).isEqualTo("Hauptstraße 42");
        assertThat(residence.city()).isEqualTo("München");
        assertThat(residence.country()).isEqualTo("DE");
        assertThat(residence.state()).isEqualTo("Bayern");
        assertThat(residence.zipCode()).isEqualTo("80331");
        assertThat(result.restrictedId()).isEqualTo("123456789");
    }

    @Test
    void fromIdentityData_WithFreetextPlaceOfBirth_ShouldMapToLocality() {
        // Arrange
        IdentityData identityData = new IdentityData(
            "AR",
            "DE",
            "2028-05-20",
            "Anna",
            "Schmidt",
            null,
            null,
            new DateOfBirth("1990-03-22", "19900322"),
            new Place(
                null,
                "Kleinstadt in Bayern",
                null
            ),
            "DE",
            null,
            new Place(
                new de.bdr.pidp.issuer.base.identitydata.StructuredPlace("Am Markt 7", "Hamburg", "DE", "Hamburg", "20095"),
                null,
                null
            ),
            new RestrictedId("987654321")
        );

        // Act
        PIDIdentityData result = PIDIdentityData.fromIdentityData(identityData);

        // Assert
        assertThat(result.placeOfBirth())
            .asInstanceOf(type(Locality.class))
            .extracting(Locality::locality)
            .isEqualTo("Kleinstadt in Bayern");
    }

    @Test
    void fromIdentityData_WithNoPlaceInfo_ShouldMapToNoPlaceInfo() {
        // Arrange
        IdentityData identityData = new IdentityData(
            "AF",
            "DE",
            "2027-11-10",
            "Ivan",
            "Petrov",
            null,
            null,
            new DateOfBirth("1985-07-30", "19850730"),
            new Place(
                null,
                null,
                "unbekannt"
            ),
            "FR",
            null,
            new Place(
                null,
                null,
                "unbekannt"
            ),
            new RestrictedId("456789123")
        );

        // Act
        PIDIdentityData result = PIDIdentityData.fromIdentityData(identityData);

        // Assert
        assertThat(result.placeOfBirth()).isInstanceOf(NoPlaceInfo.class);
        assertThat(result.placeOfResidence()).isInstanceOf(NoPlaceInfo.class);
    }

    @Test
    void fromIdentityData_WithMinimalData_ShouldMapCorrectly() {
        // Arrange
        IdentityData identityData = new IdentityData(
            "AS",
            null,
            "2025-01-01",
            null,
            "Müller",
            null,
            null,
            new DateOfBirth("1970-01-01", "19700101"),
            new Place(
                new de.bdr.pidp.issuer.base.identitydata.StructuredPlace(null, "Stuttgart", "DE", null, null),
                null,
                null
            ),
            "DE",
            null,
            new Place(
                new de.bdr.pidp.issuer.base.identitydata.StructuredPlace(null, null, "DE", null, null),
                null,
                null
            ),
            new RestrictedId("111111111")
        );

        // Act
        PIDIdentityData result = PIDIdentityData.fromIdentityData(identityData);

        // Assert
        assertThat(result.documentType()).isEqualTo("AS");
        assertThat(result.dateOfExpiry()).isEqualTo("2025-01-01");
        assertThat(result.givenNames()).isNull();
        assertThat(result.familyNames()).isEqualTo("Müller");
        assertThat(result.artisticName()).isNull();
        assertThat(result.academicTitle()).isNull();
        assertThat(result.dateOfBirth()).isEqualTo(new BirthDate("1970-01-01"));
        assertThat(result.placeOfBirth())
            .asInstanceOf(type(Locality.class))
            .extracting(Locality::locality)
            .isEqualTo("Stuttgart");
        assertThat(result.nationality()).isEqualTo("DE");
        assertThat(result.birthName()).isNull();
        assertThat(result.placeOfResidence()).isInstanceOf(StructuredPlace.class);
        StructuredPlace residence = (StructuredPlace) result.placeOfResidence();
        assertThat(residence.street()).isNull();
        assertThat(residence.city()).isNull();
        assertThat(residence.country()).isEqualTo("DE");
        assertThat(residence.state()).isNull();
        assertThat(residence.zipCode()).isNull();
        assertThat(result.restrictedId()).isEqualTo("111111111");
    }

    @Test
    void fromIdentityData_WithNullValues_ShouldThrowNullPointerException() {
        // Arrange
        IdentityData identityData = new IdentityData(
            null,
            null,
            "2026-06-15",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        );

        // Act & Assert
        assertThatThrownBy(() -> PIDIdentityData.fromIdentityData(identityData))
            .isInstanceOf(NullPointerException.class);
    }
}
