/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import java.util.UUID;

public class ClientIds {
    public static UUID validClientIdForSelfSigned() {
        return UUID.fromString("124f1f23-7c5c-4659-b539-2f6f7fdb51cf");
    }

    public static UUID validClientIdForChain() {
        return UUID.fromString("152e7566-b336-11f0-9e91-00155d50d2a8");
    }
}
