/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.base.JSONRepresentation;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.List;
import java.util.Map;

@NullMarked
public interface CredentialIssuerMetadata extends JSONRepresentation {

    Issuer credentialIssuer();

    URI credentialEndpoint();

    @Nullable
    URI nonceEndpoint();

    @Nullable
    CredentialRequestEncryption credentialRequestEncryption();

    @Nullable
    CredentialResponseEncryption credentialResponseEncryption();

    @Nullable
    BatchCredentialIssuance batchCredentialIssuance();

    /**
     * @return the configured batch size in {@link CredentialIssuerMetadataImpl.BatchCredentialIssuance} if set, otherwise the max batch size is one
     */
    int evaluateMaxBatchSize();

    @Nullable
    List<Display> displays();

    Map<CredentialConfigurationID, CredentialConfiguration> credentialConfigurationsSupported();


    interface BatchCredentialIssuance extends JSONRepresentation {
        int batchSize();
    }


    interface Display extends JSONRepresentation {
        @Nullable
        String name();

        @Nullable
        String locale();
    }
}
