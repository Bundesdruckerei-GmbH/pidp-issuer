/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.Scope;
import de.bdr.pidp.issuer.base.JSONRepresentation;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

@NullMarked
public interface CredentialConfiguration extends JSONRepresentation {
    String format();

    @Nullable
    Scope scope();

    @Nullable
    List<JWSAlgorithm> credentialSigningAlgValuesSupported();

    @Nullable
    List<CryptographicBindingMethod> cryptographicBindingMethodsSupported();

    @Nullable
    Map<SupportedProofType, ProofType> proofTypesSupported();

    @Nullable
    CredentialMetadata credentialMetadata();

    interface SdJwt extends CredentialConfiguration {
        String vct();
    }

    interface Mdoc extends CredentialConfiguration {
        String doctype();
    }
}
