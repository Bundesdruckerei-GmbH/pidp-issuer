/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.config;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.List;

@NullMarked
class AuthMetadata extends AuthorizationServerMetadata implements ReadOnlyAuthMetadata {

    @Nullable
    private List<JWSAlgorithm> clientAttestationSigningAlgValuesSupported;
    @Nullable
    private List<JWSAlgorithm> clientAttestationPoPSigningAlgValuesSupported;
    @Nullable
    private URI challengeEndpoint;

    /**
     * Creates a new OAuth 2.0 Authorisation Server (AS) metadata instance.
     *
     * @param issuer The issuer identifier. Must be a URI using the https
     *               scheme with no query or fragment component. Must not
     *               be {@code null}.
     */
    public AuthMetadata(Issuer issuer) {
        super(issuer);
    }

    public void setClientAttestationSigningAlgValuesSupported(List<JWSAlgorithm> values) {
        clientAttestationSigningAlgValuesSupported = values;
        setCustomParameter("client_attestation_signing_alg_values_supported", values.stream().map(Algorithm::getName).toList());
    }

    public void setClientAttestationPoPSigningAlgValuesSupported(List<JWSAlgorithm> values) {
        clientAttestationPoPSigningAlgValuesSupported = values;
        setCustomParameter("client_attestation_pop_signing_alg_values_supported", values.stream().map(Algorithm::getName).toList());
    }

    public void setChallengeEndpointURI(URI endpoint) {
        this.challengeEndpoint = endpoint;
        setCustomParameter("challenge_endpoint", endpoint.toString());
    }

    @Override
    public @Nullable List<JWSAlgorithm> getClientAttestationSigningAlgValuesSupported() {
        return clientAttestationSigningAlgValuesSupported;
    }

    @Override
    public @Nullable List<JWSAlgorithm> getClientAttestationPoPSigningAlgValuesSupported() {
        return clientAttestationPoPSigningAlgValuesSupported;
    }

    @Override
    public @Nullable URI getChallengeEndpoint() {
        return challengeEndpoint;
    }
}
