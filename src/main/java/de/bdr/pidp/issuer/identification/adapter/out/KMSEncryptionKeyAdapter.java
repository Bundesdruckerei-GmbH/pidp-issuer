/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.out;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.identification.port.out.EncryptionKeyPortOut;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.RawTransitKey;
import org.springframework.vault.support.TransitKeyType;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
class KMSEncryptionKeyAdapter implements EncryptionKeyPortOut {

    private final VaultTemplate vaultTemplate;
    private final String transitPath;

    public KMSEncryptionKeyAdapter(VaultTemplate vaultTemplate, IdentificationConfiguration config) {
        this.vaultTemplate = vaultTemplate;
        transitPath = config.getKms().getTransitPath();
    }

    @Override
    public SecretKey fetchEncryptionKey(VersionedKeyID kid) {
        var rawKey = vaultTemplate.opsForTransit(transitPath).exportKey(kid.keyID().value(), TransitKeyType.ENCRYPTION_KEY);
        if (rawKey == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }
        var keyByVersion = rawKey.getKeys().get(String.valueOf(kid.version()));
        var decodedKey = Base64.getDecoder().decode(keyByVersion);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    @Override
    public JWKSet fetchEncryptionKeySet(VersionedKeyID kid) {
        var rawKey = vaultTemplate.opsForTransit(transitPath).exportKey(kid.keyID().value(), TransitKeyType.ENCRYPTION_KEY);
        if (rawKey == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }
        return fromSecretKey(rawKey);
    }

    @Override
    public int getLatestVersion(KeyID kid) {
        var vaultKey = vaultTemplate.opsForTransit(transitPath).getKey(kid.value());
        if (vaultKey == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }
        return vaultKey.getLatestVersion();
    }

    private JWKSet fromSecretKey(RawTransitKey rawKey) {
        var keyID = new KeyID(rawKey.getName());
        var jwks = rawKey.getKeys().entrySet().stream().map(e -> {
            var decodedKey = Base64.getDecoder().decode(e.getValue());
            var secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            var kid = new VersionedKeyID(keyID, Integer.parseInt(e.getKey()));
            return (JWK) new OctetSequenceKey.Builder(secretKey)
                .keyID(kid.toString())
                .build();
        }).toList();
        return new JWKSet(jwks);
    }
}
