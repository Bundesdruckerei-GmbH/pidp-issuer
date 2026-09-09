/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import com.nimbusds.jwt.JWTClaimsSet;
import de.bdr.pidp.issuer.base.identitydata.DateOfBirth;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.identitydata.Place;
import de.bdr.pidp.issuer.base.identitydata.RestrictedId;
import de.bdr.pidp.issuer.base.identitydata.StructuredPlace;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.text.ParseException;
import java.util.Base64;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class PidTestData {

    public static final JWTClaimsSet TEST_SEED_CREDENTIAL_CLAIMS;

    public static final IdentityData TEST_IDENTITY_DATA = new IdentityData(
        DocumentType.ID.name(),
        null,
        "2046-01-23",
        "ERIKA",
        "MUSTERMANN",
        "MUSTERFRAU",
        "DR",
        new DateOfBirth(null, "19640812"),
        new Place(null, "BERLIN", null),
        "D",
        "GABLER",
        new Place(new StructuredPlace("HEIDESTRASSE 17", "KÖLN", "D", "NRW", "51147"), null, null),
        new RestrictedId("RVJJS0E=")
    );

    public static final IdentityData TEST_IDENTITY_DATA_2 = new IdentityData(
        "AR",
        null,
        "2046-01-23",
        "John",
        "Doe",
        null,
        null,
        new DateOfBirth("1953-06-17", "19530617"),
        new Place(null, "Washington", null),
        "USA",
        null,
        new Place(null, "Keine Wohnung in Deutschland", null),
        new RestrictedId(Base64.getUrlEncoder().encodeToString("John".getBytes()))
    );

    public static final String IDENTITY_DATA_NAMESPACE = "https://pid-provider.bundesdruckerei.de/identity_data";

    static {
        try {
            TEST_SEED_CREDENTIAL_CLAIMS = JWTClaimsSet.parse("""
                {
                    "aud": "http://localhost:8080",
                    "sub": "RVJJS0E=",
                    "exp": 2400317724,
                    "https://pid-provider.bundesdruckerei.de/identity_data": {
                        "place_of_birth": {
                            "freetext_place": "BERLIN"
                        },
                        "family_names": "MUSTERMANN",
                        "nationality": "D",
                        "date_of_expiry": "2046-01-23",
                        "date_of_birth": {
                            "date_string": "19640812"
                        },
                        "birth_name": "GABLER",
                        "place_of_residence": {
                            "structured_place": {
                                "country": "D",
                                "state": "NRW",
                                "city": "KÖLN",
                                "street": "HEIDESTRASSE 17",
                                "zip_code": "51147"
                            }
                        },
                        "given_names": "ERIKA",
                        "artistic_name": "MUSTERFRAU",
                        "academic_title": "DR",
                        "document_type": "ID",
                        "restricted_id": {
                            "id": "RVJJS0E="
                        }
                    },
                    "iat": 1769165724,
                    "jti": "019bea7e-9b6a-72e0-a06c-c006cff2b83a"
                }
                """);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
