/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import net.minidev.json.JSONObject;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public interface JSONRepresentation {

    JSONObject toJSONObject();

    static List<JSONObject> toJSONArray(List<? extends JSONRepresentation> representations) {
        return representations.stream().map(JSONRepresentation::toJSONObject).toList();
    }

    static <T> Map<T, JSONObject> toJSONMap(Map<T, ? extends JSONRepresentation> representations) {
        return representations.entrySet().stream()
            .collect(Collectors.toUnmodifiableMap(
                Map.Entry::getKey,
                v -> v.getValue().toJSONObject()));
    }
}
