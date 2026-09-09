/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;
import lombok.Getter;
import lombok.experimental.Accessors;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;

import java.util.List;

@Getter
@Accessors(fluent = true)
@NullMarked
public class CredentialResponseEncryptionImpl implements CredentialResponseEncryption {

    private final List<JWEAlgorithm> algValuesSupported;
    private final List<EncryptionMethod> encValuesSupported;
    private final boolean encryptionRequired;

    public CredentialResponseEncryptionImpl(List<JWEAlgorithm> algValuesSupported, List<EncryptionMethod> encValuesSupported, boolean encryptionRequired) {
        this.algValuesSupported = algValuesSupported;
        this.encValuesSupported = encValuesSupported;
        this.encryptionRequired = encryptionRequired;
    }

    @Override
    public JSONObject toJSONObject() {
        JSONObject o = new OrderedJSONObject();

        var algValues = algValuesSupported.stream().map(Algorithm::getName).toList();
        o.put("alg_values_supported", algValues);

        var encValues = encValuesSupported.stream().map(Algorithm::getName).toList();
        o.put("enc_values_supported", encValues);

        o.put("encryption_required", encryptionRequired);

        return o;
    }
}
