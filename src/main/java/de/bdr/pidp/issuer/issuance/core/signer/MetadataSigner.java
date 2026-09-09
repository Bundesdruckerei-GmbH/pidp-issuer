/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyType;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.config.MetadataSignerConfiguration;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

@Component
@Getter
public class MetadataSigner {
    private final ECKey signerKey;
    private final ECDSASigner signer;
    private final X509Certificate accessCertificate;

    public MetadataSigner(FileResourceHelper fileResourceHelper, MetadataSignerConfiguration metadataSignerConfiguration) {
        try {
            var keystore = fileResourceHelper.readKeyStore(metadataSignerConfiguration.getSignerPath(), metadataSignerConfiguration.getSignerPassword());
            signerKey = ECKey.load(keystore, metadataSignerConfiguration.getSignerAlias(), metadataSignerConfiguration.getSignerPassword().toCharArray());
            if (signerKey == null) {
                throw new PidServerException("Metadata keystore could not be loaded: Key not found in keystore.");
            }
            if (!isEC256Key(signerKey)) {
                throw new PidServerException("Metadata keystore could not be loaded: Key is not EC256 key.");
            }
            signer = new ECDSASigner(signerKey);

            accessCertificate = (X509Certificate) keystore.getCertificate(metadataSignerConfiguration.getAccessCertificateAlias());
            if (accessCertificate == null) {
                throw new PidServerException("Metadata keystore could not be loaded: Access certificate not found in keystore");
            }

        } catch (JOSEException | KeyStoreException e) {
            throw new PidServerException("Metadata keystore could not be loaded.", e);
        }
    }

    private boolean isEC256Key(ECKey key) {
        return KeyType.EC.equals(key.getKeyType()) && Curve.P_256.equals(key.getCurve());
    }
}
