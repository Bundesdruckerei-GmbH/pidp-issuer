/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.base.constants.RefreshTokenClaims;
import de.bdr.pidp.issuer.base.jwt.JOSEObjectTypes;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

public class TestRefreshTokenIssuer {

    public static final ECKey SIGNING_EC_KEY = TestUtils.generateEcKey384();
    private static final String DUMMY_SEED_CREDENTIAL = "eyJraWQiOiJwcF9zZWVkX2tlX3N5bWtfbG9jYWwvMSIsImN0eSI6IkpXVCIsInR5cCI6InNlZWQtY3JlZGVudGlhbCtqd3QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.K_2FU6Uizy_mXRE5WMBQgD-C-fLomL4A8jSLUr_N80l6_idfCs9zvQ.fiupvqm7Y_RgkSe9.JTgFRT8Jwozc-nUyabXERdOlRwYjgjGXJAmbw3aRKh8k0z0ZjXEd8ktHSGhwGdUfVG7mZuga1kaNMHfcfArRDpPOuUFcdy3s9mOaRsDeXp-rlRn5G_d2aabyPAmA1fKIC1wcwPcUP-0dlwaI3MCYvGFnyKtq7q3qeuAu5kJM1t0YZvo7WNFD8Bk1XUou7nKLRFGs-8tNenS5ti1dPH8mWzDFPKn9jyutzZAckaOsc9d8ZJSOi8pTYNWKhKvkc0D-bpi7KXxrLXVdJqRZs8NNp0irqP8LS2gocrwe8NvSs-NKCzTUq8l8AvxgykI5uGeEywuyatfuKxNOFNtMRyreak_MAsnR9pxtepV-x_YYHR7lw4eiMx2JLPf0xdjBWJluYOcL92j4MO5vxsGrYEVXSkX69QCpSJU7jNkgjOpbcAZNYKUkvABlztWYWyVohii-eNluGX5mqWdcaowm6THoiG5R2XgGU24v7JCGrZ8anj7Nd083Yykp5B00G616eOBoy_uwxpaHK09dsQpHXJwOZyUsOOKiWZ5Gh_pON5-KOP9aMdw7UHcmFWm-L3M3yUYeQvx39b3dsNjm1d7EyYHqDMo8v_F0gAr2oYBKtutiGo0QJBEfO5dBBGpu580qFH9H0aE4RvlBx-EBQYUsqSmvwFmAbdTh4IU5k8SCltgzQjkvI_M5NIEnj3nI-s53RpAkd6tWueXvRedzPPnAXQ5XBzZiHYsMn6NrsZUcJdz1RzDz5yW6V3a8g8nLcYnfUela7t9Ylf6lYKOkhHs27xtcXvy5FqhYN6eDM1dj05EvFvAStnbdC8JY0k5CQYVv72rJp6UgZQA-ZNCuxEUQEVV453KztwQoPCg2BwrBZGCRquFi9D1iLhG0NUsXl0edaapkYs9G0y7_bpRPcVB0ItrS7oG0NgMB4O9oGn7KbDRuZGpintl_bz08X5wEYfnTlc5qmKMi15TxU8NKMBvgVm4XPH5kQfalQw2KrYIGvY9Dignbx9UUt5LstDSJ3HnUpJjl0EYBOLH74L06-LzJioQUoPoCanUgSk6hB8TEVrJyCxyoQmjYN4ETqJSsWps0nH8i1drBX401P-yqnTXNvdZeX9LEkhWSrpF_JuVAYO0forlCv5Ls-FE-AFNsBP4vfbc1Sgs8D3dfhxhhAYbLaKSuWZDaBGjk9we6wJ4VEdIGVBpCDBa9OQArzhK_24FWEO2e5srt8BQig-NqHaqnTSqB20Ouuc_PJt7MdVllENb0ocnnZ1WRLPKiwdx6_DF7Nrm8WJsmH0PEeJuvTRd7THRWLm0SfsC09Ky3jZVnoUYt-7NUjfisA1CCwraZdut_eGckQ5YsNxUMGBxirgwA0VHyYRdH1EHyNBQiNclKVaKXEDh9W_KmwIajSJY.k8xc9GVJUzTQDjTSgSyx0A";

    /**
     * Is not signed by HSM.
     * For unit tests only, not suitable for integration tests.
     */
    public static SignedJWT buildRefreshToken(JWTClaimsSet claims) {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES384)
            .type(JOSEObjectTypes.REFRESH_TOKEN)
            .keyID(SIGNING_EC_KEY.getKeyID())
            .build();

        var jwt = new SignedJWT(header, claims);

        try {
            var signer = new ECDSASigner(SIGNING_EC_KEY);
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwt;
    }

    public static SignedJWT buildRefreshToken() {
        var claims = defaultClaims(Base64URL.encode("dummy")).build();
        return buildRefreshToken(claims);
    }

    public static JWTClaimsSet.Builder defaultClaims(Base64URL jkt) {
        var cnf = new JWKThumbprintConfirmation(jkt).toJWTClaim();
        var now = Instant.now();

        return new JWTClaimsSet.Builder()
            .issuer(TestConfig.pidiBaseUrl())
            .subject("pseudonym")
            .issueTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .claim(RefreshTokenClaims.CLIENT_ID, ClientIds.validClientIdForSelfSigned().toString())
            .claim(RefreshTokenClaims.SCOPE, "pid")
            .claim(cnf.getKey(), cnf.getValue())

            .audience(TestConfig.pidiBaseUrl())
            .expirationTime(Date.from(now.plus(Duration.ofDays(730))))
            .claim(RefreshTokenClaims.SEED_CREDENTIAL, DUMMY_SEED_CREDENTIAL);
    }

}
