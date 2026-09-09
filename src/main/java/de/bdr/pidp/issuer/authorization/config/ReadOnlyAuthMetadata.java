/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.List;

public interface ReadOnlyAuthMetadata extends ReadOnlyAuthorizationServerMetadata {

    List<JWSAlgorithm> getClientAttestationSigningAlgValuesSupported();
    List<JWSAlgorithm> getClientAttestationPoPSigningAlgValuesSupported();
    @Nullable
    URI getChallengeEndpoint();
    default boolean isChallengeSupported() {
        return getChallengeEndpoint() != null;
    }
}
