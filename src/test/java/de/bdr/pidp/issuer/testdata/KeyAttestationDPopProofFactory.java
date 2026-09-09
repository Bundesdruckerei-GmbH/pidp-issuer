/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.net.URI;
import java.util.Date;

public class KeyAttestationDPopProofFactory extends DefaultDPoPProofFactory {

    public KeyAttestationDPopProofFactory(JWK jwk, JWSAlgorithm jwsAlg) throws JOSEException {
        super(jwk, jwsAlg);
    }

    public SignedJWT createDPoPJWT(final JWTID jti,
                                   final String htm,
                                   final URI htu,
                                   final Date iat,
                                   final AccessToken accessToken,
                                   final Nonce nonce,
                                   final SignedJWT keyAttestation)
            throws JOSEException {

        var jwsHeaderBuilder = new JWSHeader.Builder(getJWSAlgorithm())
                .type(DPoPProofFactory.TYPE)
                .jwk(getPublicJWK());
        var jwsHeader = jwsHeaderBuilder.build();

        JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(jti, htm, htu, iat, accessToken, nonce);
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
        jwtClaimsSetBuilder.claim("key_attestation", keyAttestation.serialize());

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        signedJWT.sign(getJWSSigner());
        return signedJWT;
    }
}
