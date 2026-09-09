/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;
import lombok.Data;
import lombok.experimental.Accessors;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.List;
import java.util.Map;

@Data
@Accessors(fluent = true)
@NullMarked
public class CredentialIssuerMetadataImpl implements CredentialIssuerMetadata {

    private final Issuer credentialIssuer;
    private final URI credentialEndpoint;
    private final Map<CredentialConfigurationID, CredentialConfiguration> credentialConfigurationsSupported;

    @Nullable
    private URI nonceEndpoint;
    @Nullable
    private CredentialRequestEncryption credentialRequestEncryption;
    @Nullable
    private CredentialResponseEncryption credentialResponseEncryption;
    @Nullable
    private BatchCredentialIssuance batchCredentialIssuance;
    @Nullable
    private List<CredentialIssuerMetadata.Display> displays;

    @Override
    public int evaluateMaxBatchSize() {
        var batchIssuance = batchCredentialIssuance();
        return batchIssuance != null ? batchIssuance.batchSize() : 1;
    }

    @Override
    public JSONObject toJSONObject() {
        JSONObject o = new OrderedJSONObject();
        o.put("credential_issuer", credentialIssuer.getValue());
        o.put("credential_endpoint", credentialEndpoint.toString());

        if (nonceEndpoint != null) {
            o.put("nonce_endpoint", nonceEndpoint.toString());
        }
        if (credentialRequestEncryption != null) {
            o.put("credential_request_encryption", credentialRequestEncryption.toJSONObject());
        }
        if (credentialResponseEncryption != null) {
            o.put("credential_response_encryption", credentialResponseEncryption.toJSONObject());
        }
        if (batchCredentialIssuance != null) {
            o.put("batch_credential_issuance", batchCredentialIssuance.toJSONObject());
        }
        if (displays != null) {
            o.put("display", displays.stream().map(CredentialIssuerMetadata.Display::toJSONObject).toList());
        }

        JSONObject credConfigs = new OrderedJSONObject();
        credentialConfigurationsSupported.forEach((id, conf) -> credConfigs.put(id.getName(), conf.toJSONObject()));
        o.put("credential_configurations_supported", credConfigs);

        return o;
    }

    public record BatchCredentialIssuance(int batchSize) implements CredentialIssuerMetadata.BatchCredentialIssuance {
        @Override
        public JSONObject toJSONObject() {
            return new JSONObject().appendField("batch_size", batchSize);
        }
    }

    public record Display(@Nullable String name, @Nullable String locale) implements CredentialIssuerMetadata.Display {
        public JSONObject toJSONObject() {
            var o = new OrderedJSONObject();
            if (name != null) o.put("name", name);
            if (locale != null) o.put("locale", locale);
            return o;
        }

    }
}
