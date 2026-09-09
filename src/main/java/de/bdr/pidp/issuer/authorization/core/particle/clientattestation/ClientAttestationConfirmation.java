/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.cnf.AbstractConfirmation;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.AbstractMap;
import java.util.Map;

@NullMarked
@Getter
@RequiredArgsConstructor
public class ClientAttestationConfirmation extends AbstractConfirmation {
    private final JWK jwk;

    public static @Nullable ClientAttestationConfirmation parse(final JWTClaimsSet jwtClaimsSet) throws ParseException {
        var cnf = parseConfirmationJSONObject(jwtClaimsSet);
        if (cnf == null) {
            return null;
        }
        return parseFromConfirmationJSONObject(cnf);
    }

    private static @Nullable ClientAttestationConfirmation parseFromConfirmationJSONObject(final JSONObject cnf) throws ParseException {
        if (!cnf.containsKey("jwk")) {
            return null;
        }
        try {
            var jwkString = JSONObjectUtils.getJSONObject(cnf, "jwk");
            return new ClientAttestationConfirmation(JWK.parse(jwkString));
        } catch (java.text.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        }
    }

    @Override
    public Map.Entry<String, JSONObject> toJWTClaim() {
        JSONObject cnf = new JSONObject();
        cnf.put("jwk", jwk.toJSONObject());

        return new AbstractMap.SimpleImmutableEntry<>("cnf", cnf);
    }
}
