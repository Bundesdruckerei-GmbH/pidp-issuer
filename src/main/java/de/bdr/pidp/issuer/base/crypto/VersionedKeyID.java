/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto;

import org.jspecify.annotations.NullMarked;

import java.util.regex.Pattern;

@NullMarked
public record VersionedKeyID(KeyID keyID, int version) {

    private static final Pattern VERSIONED_KID_FORMAT = Pattern.compile("^(?<kid>.+)/(?<version>\\d+)$");

    public VersionedKeyID {
        if (version < 0) {
            throw new IllegalArgumentException("Invalid version");
        }
    }

    public static VersionedKeyID parse(String keyIDWithVersion) {
        var matcher = VERSIONED_KID_FORMAT.matcher(keyIDWithVersion);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid KeyID or version");
        }
        var keyID = new KeyID(matcher.group("kid"));
        var version = Integer.parseInt(matcher.group("version"));
        return new VersionedKeyID(keyID, version);
    }

    @Override
    public String toString() {
        return "%s/%s".formatted(keyID.value(), version);
    }
}
