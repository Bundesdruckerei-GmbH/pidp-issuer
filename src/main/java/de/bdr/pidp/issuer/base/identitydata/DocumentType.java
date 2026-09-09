/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.identitydata;

import org.jspecify.annotations.Nullable;

import java.util.Optional;

/**
 * Valid DocumentTypes are:
 * <ul>
 *     <li>"ID" for Personalausweis</li>
 *     <li>"AR", "AF" and "AS" for Aufenthaltstitel</li>
 * </ul>
 * DocumentType "UB" for Unionsbürgerkarte and "OA" for Smart-eID are not supported by PIDP-Issuer.
 * @see
 * <a href="https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03127/BSI-TR-03127_1-40.pdf?__blob=publicationFile&v=3">Technische Richtlinie TR-03127 eID-Dokumente</a>
 */
public enum DocumentType {
    ID, AR, AS, AF;

    public static Optional<String> validateDocumentType(@Nullable String documentType) {
        if (documentType == null) {
            return Optional.of("Document type must not be null");
        }

        try {
            DocumentType.valueOf(documentType);
        } catch (IllegalArgumentException _) {
            return Optional.of("Document type %s is not valid".formatted(documentType));
        }
        return Optional.empty();
    }
}
