/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;
import de.bdr.pidp.issuer.base.JSONRepresentation;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

@Data
@Accessors(fluent = true)
@NullMarked
public abstract class CredentialConfigurationImpl implements CredentialConfiguration {

    private final String format;

    @Nullable
    private Scope scope;

    @Nullable
    private List<JWSAlgorithm> credentialSigningAlgValuesSupported;

    @Setter(AccessLevel.PRIVATE)
    @Nullable
    private List<CryptographicBindingMethod> cryptographicBindingMethodsSupported;

    @Setter(AccessLevel.PRIVATE)
    @Nullable
    private Map<SupportedProofType, ProofType> proofTypesSupported;

    @Nullable
    private CredentialMetadata credentialMetadata;

    protected abstract JSONObject getFormatSpecificJSONElements();

    @Override
    public JSONObject toJSONObject() {
        JSONObject o = new OrderedJSONObject();

        o.put("format", format);

        o.merge(getFormatSpecificJSONElements());

        if (scope != null) {
            o.put("scope", scope.toString());
        }

        if (credentialSigningAlgValuesSupported != null) {
            var signingAlgs = credentialSigningAlgValuesSupported.stream().map(Algorithm::getName).toList();
            o.put("credential_signing_alg_values_supported", signingAlgs);
        }

        if (cryptographicBindingMethodsSupported != null && proofTypesSupported != null) {
            var bindingMethods = cryptographicBindingMethodsSupported.stream().map(CryptographicBindingMethod::getName).toList();
            o.put("cryptographic_binding_methods_supported", bindingMethods);

            var proofTypes = new OrderedJSONObject();
            proofTypesSupported.forEach((id, conf) -> proofTypes.put(id.getName(), conf.toJSONObject()));
            o.put("proof_types_supported", proofTypes);
        }

        if (credentialMetadata != null) {
            o.put("credential_metadata", credentialMetadata.toJSONObject());
        }

        return o;
    }

    /**
     * proof_types_supported MUST be present if cryptographic_binding_methods_supported is present, and omitted otherwise
     */
    public void cryptographicBinding(List<CryptographicBindingMethod> methodsSupported, Map<SupportedProofType, ProofType> proofTypesSupported) {
        this.cryptographicBindingMethodsSupported = methodsSupported;
        this.proofTypesSupported = proofTypesSupported;
    }

    @Getter
    public static class SdJwt extends CredentialConfigurationImpl implements CredentialConfiguration.SdJwt {

        private final String vct;

        public SdJwt(String format, String vct) {
            super(format);
            this.vct = vct;
        }

        @Override
        protected JSONObject getFormatSpecificJSONElements() {
            return new JSONObject().appendField("vct", vct);
        }
    }

    @Getter
    public static class Mdoc extends CredentialConfigurationImpl implements CredentialConfiguration.Mdoc {

        private final String doctype;

        public Mdoc(String format, String doctype) {
            super(format);
            this.doctype = doctype;
        }

        @Override
        protected JSONObject getFormatSpecificJSONElements() {
            return new JSONObject().appendField("doctype", doctype);
        }
    }
}
