/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto;

import org.jspecify.annotations.NullMarked;

import java.util.regex.Pattern;

@NullMarked
public record KeyID(String value) {

    private static final Pattern KID_FORMAT = Pattern.compile("^[A-Za-z0-9.\\-_]{1,64}$");

    public KeyID {
        if (!KID_FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid KeyID");
        }
    }
}
