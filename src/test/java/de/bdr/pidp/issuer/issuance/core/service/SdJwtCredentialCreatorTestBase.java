/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

abstract class SdJwtCredentialCreatorTestBase extends CredentialCreatorTestBase {

    protected static final int NR_DECOY_DIGESTS = 1;
    protected static final int NR_NESTED_SD_AGE_SELECTOR = 6;
    protected static final int NR_MAX_ADDRESS_PROPERTIES = 5;
    protected static final JsonMapper JSON_MAPPER = new JsonMapper();
    protected static final String EMPTY_KEY_NAME = "...";

    @NotNull
    protected static Function<String, JsonNode> toJsonNode() {
        return JSON_MAPPER::readTree;
    }

    @NotNull
    protected static List<String> getAllSdHashValues(String payload) throws JacksonException {
        JsonNode jsonNode = JSON_MAPPER.readTree(payload);
        ((ObjectNode) jsonNode).remove("status");
        return getAllSdHashes(jsonNode);
    }

    protected static List<String> getAllSdHashes(JsonNode jsonNode) {
        ArrayList<String> listSdHashes = new ArrayList<>();
        List<JsonNode> sdJsonNodes = jsonNode.findValues("_sd");
        sdJsonNodes.forEach(node -> node.forEach(value -> listSdHashes.add(value.asString())));
        return listSdHashes;
    }

    protected static String getDecodedPayload(String sdJwt) {
        String[] split = sdJwt.split("\\.");
        byte[] decodedPayload = Base64.getUrlDecoder().decode(split[1]);
        return new String(decodedPayload);
    }

    protected static String getDecodedHeader(String sdJwt) {
        String[] split = sdJwt.split("\\.");
        byte[] decodedHeader = Base64.getUrlDecoder().decode(split[0]);
        return new String(decodedHeader);
    }

    protected static String getSignature(String sdJwt) {
        String[] split = sdJwt.split("\\.");
        return split[2];
    }

    protected static List<String> getDisclosures(String decodedSignature) {
        return Arrays.stream(decodedSignature.substring(decodedSignature.indexOf('~') + 1).split("~")).toList();
    }

    protected static List<String> toHashedDisclosures(List<String> disclosures, MessageDigest messageDigest) {
        return disclosures.stream().map(disclosure -> removePadding(Base64.getUrlEncoder().encodeToString(messageDigest.digest(disclosure.getBytes())))).toList();
    }

    private static String removePadding(String value) {
        return value.replace("=", "");
    }

    protected static void verifySignature(String sdJwt, JWSVerifier verifier) {
        try {
            SignedJWT jwt = SignedJWT.parse(stripDisclosures(sdJwt));
            assertThat(jwt.verify(verifier)).isTrue();
        } catch (java.text.ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    protected static String stripDisclosures(String sdJwt) {
        return sdJwt.split("~", 2)[0];
    }

    protected static Map<String, JsonNode> parseDisclosures(List<String> disclosures) {
        Base64.Decoder urlDecoder = Base64.getUrlDecoder();
        return disclosures.stream()
            .map(disclosureJson -> new String(urlDecoder.decode(disclosureJson)))
            .map(toJsonNode())
            .collect(Collectors.toMap(SdJwtCredentialCreatorTestBase::getKeyName, SdJwtCredentialCreatorTestBase::getValueNode,
                (a, b) -> new ArrayNode(JSON_MAPPER.getNodeFactory()).add(a).add(b),
                HashMap::new));
    }

    private static String getKeyName(JsonNode node) {
        if (node.size() > 2) {
            return node.get(1).asString();
        } else {
            return EMPTY_KEY_NAME;
        }
    }

    private static JsonNode getValueNode(JsonNode node) {
        int i = (node.size() > 2) ? 2 : 1;
        return node.get(i);
    }
}
