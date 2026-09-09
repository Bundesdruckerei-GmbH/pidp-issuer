/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.HexFormat;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DigestUtil {
    public static String computeDigest(String input) {
        return HexFormat.of().formatHex(DigestUtils.sha256(input));
    }
}
