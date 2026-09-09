/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.requests;

import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WResponseBuilder {

    private final Map<String, List<String>> headers = new HashMap<>();

    private int httpStatus = 200;

    private String body = null;
    private ObjectNode jsonBody = null;

    public WResponseBuilder withHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
        return this;
    }

    public WResponseBuilder withBody(String body) {
        this.body = body;
        return this;
    }

    public WResponseBuilder withJsonBody(ObjectNode body) {
        if (jsonBody != null) {
            jsonBody.setAll(body);
        } else {
            withContentType("application/json");
            jsonBody = body;
        }
        return this;
    }

    public WResponseBuilder withContentType(String contentType) {
        return addStringHeader("content-type", contentType);
    }

    public WResponseBuilder addStringHeader(String name, String value) {
        if (headers.containsKey(name)) {
            headers.get(name).add(value);
        } else {
            ArrayList<String> values = new ArrayList<>();
            values.add(value);
            headers.put(name, values);
        }
        return this;
    }

    public ResponseEntity<JsonNode> buildJSONResponseEntity() {
        org.springframework.http.HttpHeaders httpHeaders = new org.springframework.http.HttpHeaders();
        httpHeaders.putAll(headers);
        return new ResponseEntity<>(jsonBody, httpHeaders, httpStatus);
    }

    public ResponseEntity<String> buildStringResponseEntity() {
        org.springframework.http.HttpHeaders httpHeaders = new org.springframework.http.HttpHeaders();
        httpHeaders.putAll(headers);
        return new ResponseEntity<>(body, httpHeaders, httpStatus);
    }

}
