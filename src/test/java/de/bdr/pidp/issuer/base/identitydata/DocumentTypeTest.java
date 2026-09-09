/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.identitydata;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class DocumentTypeTest {

    @ParameterizedTest
    @EnumSource(DocumentType.class)
    void validDocumentTypes(DocumentType documentType) {
        Optional<String> result = DocumentType.validateDocumentType(documentType.name());

        assertThat(result).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"IC", "UB", "OA", "id", "Id", "XX", "id_card", "a", " "})
    @NullAndEmptySource
    void invalidDocumentTypes(String value) {
        Optional<String> result = DocumentType.validateDocumentType(value);

        assertThat(result).isPresent();
    }

}
