/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.out;

import com.nimbusds.jose.jwk.JWKSet;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;

import javax.crypto.SecretKey;

public interface EncryptionKeyPortOut {

    SecretKey fetchEncryptionKey(VersionedKeyID kid);

    JWKSet fetchEncryptionKeySet(VersionedKeyID kid);

    int getLatestVersion(KeyID kid);
}
