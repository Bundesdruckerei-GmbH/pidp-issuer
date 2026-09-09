/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core;

import de.bundesdruckerei.mdoc.kotlin.core.auth.StatusListInfo;

public record StatusReference(String uri, int index) {
    public StatusListInfo toStatusListInfo() {
        return new StatusListInfo(index, uri, null);
    }
}
