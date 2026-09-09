/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.port.out.AccessTokenSigningPortOut;
import de.bdr.pidp.issuer.authorization.port.out.KMSKeyException;
import de.bdr.pidp.issuer.authorization.port.out.KeyNotFoundException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.jwk.JWKUtils;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultTransitKey;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

@Service
public class KMSAccessTokenSigningAdapter implements AccessTokenSigningPortOut {

    private final VaultTemplate vaultTemplate;
    private final String transitPath;
    private final JsonMapper jsonMapper = new JsonMapper();

    public KMSAccessTokenSigningAdapter(VaultTemplate vaultTemplate, AuthorizationConfiguration config) {
        this.vaultTemplate = vaultTemplate;
        this.transitPath = config.getKms().getTransitPath();
    }

    @Override
    public KeyAttributes getLatestVersionKeyAttributes(KeyID kid) {
        var key = vaultTemplate.opsForTransit(transitPath).getKey(kid.value());
        if (key == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }
        var vKid = new VersionedKeyID(kid, key.getLatestVersion());
        var alg = matchJWSAlgorithm(key);

        return new KeyAttributes(vKid, alg);
    }

    @Override
    public Base64URL sign(KeyID keyID, byte[] hash) {
        var path = "%s/sign/%s".formatted(transitPath, keyID.value());
        var response = vaultTemplate.write(path, Map.of(
            "input", Base64.encode(hash).toString(),
            "marshaling_algorithm", "jws"
        ));
        if (response == null || response.getData() == null || !(response.getData().get("signature") instanceof String signature)) {
            throw new KMSKeyException("Signature creation failed, empty response");
        }

        // signature is of format vault:v1:MFkwEwYHKoZIzj0... where the last part is already base64url encoded
        var parts = signature.split(":");
        var last = parts[parts.length - 1];

        return new Base64URL(last);
    }

    @Override
    public List<JWK> getPublicKeys(KeyID keyID) {
        var key = vaultTemplate.opsForTransit(transitPath).getKey(keyID.value());
        if (key == null) {
            throw new KeyNotFoundException("Key by the given keyID not found");
        }
        return key.getKeys().entrySet().stream().map(entry -> {
            var val = jsonMapper.writeValueAsString(entry.getValue());
            var pub = jsonMapper.readTree(val).get("public_key").asString();
            try {
                var jwk = JWK.parseFromPEMEncodedObjects(pub);
                var kid = new VersionedKeyID(keyID, Integer.parseInt(entry.getKey())).toString();
                return JWKUtils.extendWithKeyID(jwk, kid);
            } catch (JOSEException e) {
                throw new KMSKeyException("Could not get public key", e);
            }
        }).toList();
    }

    private JWSAlgorithm matchJWSAlgorithm(VaultTransitKey key) {
        return switch (key.getType()) {
            case "ecdsa-p256" -> JWSAlgorithm.ES256;
            case "ecdsa-p384" -> JWSAlgorithm.ES384;
            case "ecdsa-p521" -> JWSAlgorithm.ES512;
            default -> throw new KMSKeyException("Unsupported KMS key");
        };
    }

}
