/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;

import java.util.List;

public interface AccessTokenSigningPortOut {
    KeyAttributes getLatestVersionKeyAttributes(KeyID kid);
    Base64URL sign(KeyID keyID, byte[] hash);
    List<JWK> getPublicKeys(KeyID keyID);

    record KeyAttributes(VersionedKeyID keyID, JWSAlgorithm algorithm) {}
}
