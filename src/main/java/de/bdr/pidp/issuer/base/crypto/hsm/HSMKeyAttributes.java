/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;

public record HSMKeyAttributes(VersionedKeyID keyID, JWSAlgorithm algorithm) {}
