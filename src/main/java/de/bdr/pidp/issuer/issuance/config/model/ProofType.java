/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.base.JSONRepresentation;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

@NullMarked
public interface ProofType extends JSONRepresentation {

    List<JWSAlgorithm> proofSigningAlgValuesSupported();

    @Nullable
    ReadOnlyKeyAttestationsRequired keyAttestationsRequired();

    interface ReadOnlyKeyAttestationsRequired extends JSONRepresentation {

        @Nullable
        List<AttackPotentialResistance> keyStorage();

        @Nullable
        List<AttackPotentialResistance> userAuthentication();
    }
}
