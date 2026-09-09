/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.exc.InvalidDefinitionException;
import tools.jackson.databind.type.SimpleType;

import java.util.ArrayList;
import java.util.List;

public class CustomProofsDeserializer extends ValueDeserializer<List<Proof>> {
    @Override
    public List<Proof> deserialize(JsonParser parser, DeserializationContext ctx) {
        List<Proof> proofCollection = new ArrayList<>();
        JsonNode root = ctx.readTree(parser);

        final JsonNode jwts;
        final SupportedProofTypes proofType;
        if (root.has("jwt")) {
            jwts = root.get("jwt");
            proofType = SupportedProofTypes.JWT;
        } else if (root.has("attestation")) {
            jwts = root.get("attestation");
            proofType = SupportedProofTypes.ATTESTATION;
        } else {
            throw InvalidDefinitionException.from(parser, "proof_type is empty or invalid", SimpleType.constructUnsafe(Proof.class));
        }
        if (jwts.isArray()) {
            for (JsonNode jwt : jwts) {
                Proof p = switch (proofType) {
                    case JWT -> new JwtProof(jwt.asString(), JwtProofType.INSTANCE);
                    case ATTESTATION -> new AttestationProof(jwt.asString(), AttestationProofType.INSTANCE);
                };
                proofCollection.add(p);
            }
        } else {
            throw InvalidDefinitionException.from(parser, "proof_type value needs to be an array", SimpleType.constructUnsafe(Proof.class));
        }
        return proofCollection;
    }
}
