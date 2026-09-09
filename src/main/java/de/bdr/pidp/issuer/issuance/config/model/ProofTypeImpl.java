/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;
import lombok.Data;
import lombok.experimental.Accessors;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

@Data
@Accessors(fluent = true)
@NullMarked
public class ProofTypeImpl implements ProofType {

    private final List<JWSAlgorithm> proofSigningAlgValuesSupported;

    @Nullable
    private ReadOnlyKeyAttestationsRequired keyAttestationsRequired;

    @Override
    public JSONObject toJSONObject() {
        JSONObject o = new OrderedJSONObject();

        var signingAlgs = proofSigningAlgValuesSupported.stream().map(Algorithm::getName).toList();
        o.put("proof_signing_alg_values_supported", signingAlgs);

        if (keyAttestationsRequired != null) {
            o.put("key_attestations_required", keyAttestationsRequired.toJSONObject());
        }

        return o;
    }

    @Data
    public static class KeyAttestationsRequired implements ReadOnlyKeyAttestationsRequired {

        @Nullable
        private List<AttackPotentialResistance> keyStorage;

        @Nullable
        private List<AttackPotentialResistance> userAuthentication;

        @Override
        public JSONObject toJSONObject() {
            JSONObject o = new OrderedJSONObject();

            if (keyStorage != null) {
                var names = keyStorage.stream().map(AttackPotentialResistance::getName).toList();
                o.put("key_storage", names);
            }

            if (userAuthentication != null) {
                var names = userAuthentication.stream().map(AttackPotentialResistance::getName).toList();
                o.put("user_authentication", names);
            }

            return o;
        }
    }
}
