/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.out.persistence.config;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;

import java.net.URI;

@Converter(autoApply = true)
public class URITypeConverter implements AttributeConverter<URI, String> {

    @Override
    public @Nullable String convertToDatabaseColumn(@Nullable URI attribute) {
        return attribute == null ? null : attribute.toString();
    }

    @Override
    public @Nullable URI convertToEntityAttribute(@Nullable String dbData) {
        return StringUtils.isBlank(dbData) ? null : URI.create(dbData);
    }
}
