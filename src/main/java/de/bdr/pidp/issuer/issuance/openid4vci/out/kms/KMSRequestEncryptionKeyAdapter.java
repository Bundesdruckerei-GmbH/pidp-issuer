/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.kms;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.TransitKeyType;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Objects;

@NullMarked
@Service
public class KMSRequestEncryptionKeyAdapter {
    private static final String PUBLIC_KEY_IDENTIFIER = "public_key";
    private static final JWEAlgorithm ALGORITHM = JWEAlgorithm.ECDH_ES;
    private static final KeyUse KEY_USE = KeyUse.ENCRYPTION;

    private final VaultTemplate vaultTemplate;
    private final String transitPath;
    private final KeyID reqEncKaAlias;
    private final JsonMapper jsonMapper = new JsonMapper();

    public KMSRequestEncryptionKeyAdapter(VaultTemplate vaultTemplate, IssuanceConfiguration config) {
        this.vaultTemplate = vaultTemplate;
        this.transitPath = config.getKms().getTransitPath();
        this.reqEncKaAlias = new KeyID(config.getCreqEncKaAlias());
    }

    public JWK getLatestPublicKey() {
        var transitKey = vaultTemplate.opsForTransit(transitPath).getKey(reqEncKaAlias.value());
        if (transitKey == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }
        var latest = String.valueOf(transitKey.getLatestVersion());
        var keyAttributes = Objects.requireNonNull(transitKey.getKeys().get(latest));
        var pubPem = jsonMapper.valueToTree(keyAttributes).get(PUBLIC_KEY_IDENTIFIER).asString();
        try {
            var jwk = JWK.parseFromPEMEncodedObjects(pubPem);
            var keyID = new VersionedKeyID(reqEncKaAlias, transitKey.getLatestVersion());
            return extendWithEncKeyProperties(jwk, keyID.toString());
        } catch (JOSEException e) {
            throw new KMSKeyException("Could not get public key", e);
        }
    }

    public List<JWK> getPrivateKeys() {
        var rawKey = vaultTemplate.opsForTransit(transitPath).exportKey(reqEncKaAlias.value(), TransitKeyType.SIGNING_KEY);
        if (rawKey == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }

        return rawKey.getKeys().entrySet().stream().map(versionKeyEntry -> {
            JWK jwk;
            try {
                jwk = JWK.parseFromPEMEncodedObjects(versionKeyEntry.getValue());
            } catch (JOSEException e) {
                throw new KMSKeyException("Could not parse key", e);
            }
            var keyID = new VersionedKeyID(reqEncKaAlias, Integer.parseInt(versionKeyEntry.getKey()));
            return extendWithEncKeyProperties(jwk, keyID.toString());
        }).toList();
    }

    private JWK extendWithEncKeyProperties(JWK jwk, String keyID) {
        return new ECKey.Builder(jwk.toECKey())
            .keyID(keyID)
            .algorithm(ALGORITHM)
            .keyUse(KEY_USE)
            .build();
    }
}
