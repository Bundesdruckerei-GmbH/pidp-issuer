/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

import CryptoServerAPI.CryptoServerException;
import CryptoServerCXI.CryptoServerCXI;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.X509CertUtils;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class HSMSigningService {
    private static final int SIGN_MECHANISM_PARAMETER = 0;

    private final HSMAuthenticationService authService;

    HSMSigningService(HSMAuthenticationService authService) {
        this.authService = authService;
    }

    public HSMKeyAttributes getLatestVersionKeyAttributes(KeyID keyID) {
        var attributes = getKeyAttributes(keyID).stream()
            .reduce((k1, k2) -> k1.getSpecifier() > k2.getSpecifier() ? k1 : k2)
            .orElseThrow(() -> new KeyNotFoundException("Key by the given keyID not found"));
        return new HSMKeyAttributes(new VersionedKeyID(keyID, attributes.getSpecifier()), getJWSAlgorithm(attributes));
    }

    public byte[] getCertificate(VersionedKeyID keyID) {
        try {
            authService.ensureAuthenticated();

            var keyAttributes = constructKeyAttributes(keyID);
            CryptoServerCXI.Key key = authService.getCxi().findKey(keyAttributes);
            if (key == null) {
                throw new KeyNotFoundException("Key by the given keyID not found");
            }
            var attributes = authService.getCxi().getKeyAttributes(key, true);
            var cert = attributes.getCertificate();
            if (cert == null || cert.length == 0) {
                throw new HSMKeyException("Key does not contain certificate");
            }
            return cert;
        } catch (CryptoServerException | IOException e) {
            throw new HSMKeyException(e);
        }
    }

    public X509Certificate getX509Certificate(VersionedKeyID versionedKeyID) {
        var rawCert = getCertificate(versionedKeyID);
        try {
            return X509CertUtils.parseWithException(rawCert);
        } catch (CertificateException e) {
            throw new PidServerException("Certificate could not be parsed", e);
        }
    }

    public byte[] sign(VersionedKeyID keyID, byte[] hash) {
        try {
            authService.ensureAuthenticated();

            var keyAttributes = constructKeyAttributes(keyID);
            CryptoServerCXI.Key key = authService.getCxi().findKey(keyAttributes);
            if (key == null) {
                throw new KeyNotFoundException("Key by the given keyID not found");
            }

            return authService.getCxi().sign(key, SIGN_MECHANISM_PARAMETER, hash);
        } catch (CryptoServerException | IOException e) {
            throw new HSMKeyException(e);
        }
    }

    private List<CryptoServerCXI.KeyAttributes> getKeyAttributes(KeyID kid) {
        try {
            authService.ensureAuthenticated();

            var searchAttributes = constructKeyAttributes(kid);
            var attributes = authService.getCxi().listKeys(searchAttributes);

            return Arrays.stream(attributes).toList();
        } catch (CryptoServerException | IOException e) {
            throw new HSMKeyException(e);
        }
    }

    private CryptoServerCXI.KeyAttributes constructKeyAttributes(VersionedKeyID keyID) throws CryptoServerException {
        var keyAttributes = constructKeyAttributes(keyID.keyID());
        keyAttributes.setSpecifier(keyID.version());

        return keyAttributes;
    }

    private CryptoServerCXI.KeyAttributes constructKeyAttributes(KeyID kid) throws CryptoServerException {
        var keyAttributes = new CryptoServerCXI.KeyAttributes();
        keyAttributes.setName(kid.value());
        keyAttributes.setGroup(authService.getGroup());

        return keyAttributes;
    }

    private JWSAlgorithm getJWSAlgorithm(CryptoServerCXI.KeyAttributes keyAttributes) {
        if (keyAttributes.getAlgo() != CryptoServerCXI.KEY_ALGO_ECDSA) {
            throw new HSMKeyException("Unsupported HSM key");
        }
        return switch (keyAttributes.getSize()) {
            case 256 -> JWSAlgorithm.ES256;
            case 384 -> JWSAlgorithm.ES384;
            case 512 -> JWSAlgorithm.ES512;
            default -> throw new HSMKeyException("Unsupported HSM key size");
        };
    }
}
