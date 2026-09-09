/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.doc.in;

import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.CollectionType;

import java.util.ArrayList;
import java.util.List;

@Component("credentialConfigurationDocParser")
public class StringToListOfCredentialConfigurationDocParser {
    private static final JsonMapper JSON_MAPPER = new JsonMapper();

    public List<CredentialConfigurationDoc> parse(String json) {
        if (json.trim().isEmpty()) {
            return new ArrayList<>();
        }

        CollectionType listType = JSON_MAPPER.getTypeFactory()
            .constructCollectionType(List.class, CredentialConfigurationDoc.class);
        return JSON_MAPPER.readValue(json, listType);
    }
}
