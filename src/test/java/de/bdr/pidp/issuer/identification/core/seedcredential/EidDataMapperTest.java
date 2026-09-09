/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.identification.core.exception.InvalidEidData;
import de.bdr.pidp.issuer.testdata.PidTestData;
import de.bund.bsi.eid240.PersonalDataType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.stream.Stream;

import static de.bdr.pidp.issuer.identification.core.ValidEidData.TEST_PERSONAL_DATA_TYPE;
import static de.bdr.pidp.issuer.identification.core.ValidEidData.TEST_PERSONAL_DATA_TYPE_2;
import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA_2;
import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_SEED_CREDENTIAL_CLAIMS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class EidDataMapperTest {

    private static final String AUDIENCE = "http://pidi-audience";
    private final EidDataMapper mapper = new EidDataMapper(AUDIENCE);


    private static Stream<Arguments> personalDataTypesToIdentityData() {
        return Stream.of(
            Arguments.of(TEST_PERSONAL_DATA_TYPE, TEST_IDENTITY_DATA),
            Arguments.of(TEST_PERSONAL_DATA_TYPE_2, TEST_IDENTITY_DATA_2)
        );
    }

    @ParameterizedTest
    @MethodSource("personalDataTypesToIdentityData")
    void successMapPersonalDataTypeToIdentityData(PersonalDataType personalDataType, IdentityData identityData) {

        var result = mapper.map(personalDataType);
        assertThat(result)
            .isNotNull()
            .isInstanceOf(IdentityData.class)
            .isEqualTo(identityData);
    }

    @Test
    void mapSeedCredentialClaims() throws ParseException {
        var result = mapper.map(TEST_SEED_CREDENTIAL_CLAIMS);

        assertThat(result).isEqualTo(TEST_IDENTITY_DATA);
    }

    @ParameterizedTest
    @MethodSource("personalDataTypesToIdentityData")
    void successMapIdentityDataAndClaimSet(PersonalDataType personalDataType, IdentityData identityData) {

        JWTClaimsSet jwtClaimsSet = assertDoesNotThrow(() -> mapper.map(identityData));

        assertThat(jwtClaimsSet.getIssueTime()).isBeforeOrEqualTo(new Date());
        assertThat(jwtClaimsSet.getAudience()).containsExactly(AUDIENCE);
        assert identityData.restrictedId() != null;
        assertThat(jwtClaimsSet.getSubject()).isEqualTo(identityData.restrictedId().id());
        IdentityData mapped = assertDoesNotThrow(() -> mapper.map(jwtClaimsSet));

        assertThat(mapped).isEqualTo(identityData);
    }

    @Test
    void mapSeedCredentialClaimsUnknownProperties() throws ParseException {
        var jsonObject = new HashMap<>(TEST_SEED_CREDENTIAL_CLAIMS.toJSONObject());
        var namespaceClaim = new HashMap<>(JSONObjectUtils.getJSONObject(jsonObject, PidTestData.IDENTITY_DATA_NAMESPACE));
        namespaceClaim.put("Ich suche keinen Ärger", "meist findet der Ärger mich");
        jsonObject.put(PidTestData.IDENTITY_DATA_NAMESPACE, namespaceClaim);
        var claims = JWTClaimsSet.parse(jsonObject);

        assertThatThrownBy(() -> mapper.map(claims))
            .isInstanceOf(ParseException.class);
    }

    @Test
    void mapSeedCredentialMissingNamespace() throws ParseException {
        var jsonObject = new HashMap<>(TEST_SEED_CREDENTIAL_CLAIMS.toJSONObject());
        jsonObject.remove(PidTestData.IDENTITY_DATA_NAMESPACE);
        var claims = JWTClaimsSet.parse(jsonObject);

        assertThatThrownBy(() -> mapper.map(claims))
            .isInstanceOf(ParseException.class);
    }

    @Test
    void errorWhenDateOfExpiryNullAtPersonalDataType() {
        PersonalDataType personalDataType = new PersonalDataType();
        personalDataType.setDateOfExpiry(null);

        assertThatThrownBy(() -> mapper.map(personalDataType))
            .isInstanceOf(InvalidEidData.class)
            .hasMessage("The identification data is invalid or incomplete.");
    }

    @Test
    void errorWhenDateOfExpiryThrowExceptionAtParsing() {
        IdentityData invalidIdentityData = new IdentityData(
            DocumentType.ID.name(),
            null,
            "InvalidDate",
            "ERIKA",
            "MUSTERMANN",
            null,
            null,
            new DateOfBirth(null, "19640812"),
            new Place(null, "BERLIN", null),
            "D",
            null,
            null,
            new RestrictedId("RVJJS0E=")
        );

        assertThatThrownBy(() -> mapper.map(invalidIdentityData))
            .isInstanceOf(InvalidEidData.class)
            .hasMessage("The identification data is invalid or incomplete.");
    }
}
