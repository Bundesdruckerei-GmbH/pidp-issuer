/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import de.bdr.pidp.issuer.base.JSONRepresentation;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

@NullMarked
public interface CredentialMetadata extends JSONRepresentation {

    @Nullable
    List<Display> display();

    @Nullable
    List<Claim> claims();

    interface Claim extends JSONRepresentation {
        List<String> path();

        @Nullable
        List<Display> display();
    }

    interface Display extends JSONRepresentation {
        String name();

        @Nullable
        String locale();
    }
}
