/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;
import lombok.Getter;
import lombok.experimental.Accessors;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;

import java.util.List;

@Accessors(fluent = true)
@NullMarked
public class CredentialRequestEncryptionImpl implements CredentialRequestEncryption {

    private final RequestEncryptionJWKSupplier jwkSupplier;
    @Getter
    private final List<EncryptionMethod> encValuesSupported;
    @Getter
    private final boolean encryptionRequired;

    public CredentialRequestEncryptionImpl(RequestEncryptionJWKSupplier jwkSupplier, List<EncryptionMethod> encValuesSupported, boolean encryptionRequired) {
        this.jwkSupplier = jwkSupplier;
        this.encValuesSupported = encValuesSupported;
        this.encryptionRequired = encryptionRequired;
    }

    @Override
    public JWKSet jwks() {
        return jwkSupplier.jwks();
    }

    @Override
    public JSONObject toJSONObject() {
        JSONObject o = new OrderedJSONObject();

        var jwks = jwkSupplier.jwks().toJSONObject();
        o.put("jwks", jwks);

        var encValues = encValuesSupported.stream().map(Algorithm::getName).toList();
        o.put("enc_values_supported", encValues);

        o.put("encryption_required", encryptionRequired);

        return o;
    }
}
