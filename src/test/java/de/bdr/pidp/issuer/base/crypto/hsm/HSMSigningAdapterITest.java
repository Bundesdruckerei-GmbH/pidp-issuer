/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.X509CertUtils;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(properties = "hsm.enabled=true")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class HSMSigningAdapterITest {

    public static final byte[] DATA_TO_SIGN = "credential for signing".getBytes(StandardCharsets.UTF_8);

    @Autowired
    private IssuanceConfiguration configuration;

    @Autowired
    private HSMSigningService hsmSigningIssuance;

    private KeyID eccKey;
    private VersionedKeyID eccKeyV0;

    @BeforeAll
    void setup() {
        eccKey = new KeyID(configuration.getPidSigAliasHsm());
        eccKeyV0 = new VersionedKeyID(eccKey, 0);
    }

    @Test
    void getLatestVersionKeyAttributes() {
        var keyAttributes = hsmSigningIssuance.getLatestVersionKeyAttributes(eccKey);

        assertThat(keyAttributes.keyID()).isEqualTo(eccKeyV0);
        assertThat(keyAttributes.algorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void getLatestVersionKeyAttributesFromUnknownKey() {
        var kid = new KeyID("unknown");
        assertThatThrownBy(() -> hsmSigningIssuance.getLatestVersionKeyAttributes(kid))
            .isInstanceOf(KeyNotFoundException.class);
    }

    @Test
    void signAndVerify() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, JOSEException {
        var input = MessageDigest.getInstance("SHA-256").digest(DATA_TO_SIGN);
        byte[] signature = hsmSigningIssuance.sign(eccKeyV0, input);
        assertThat(signature).isNotEmpty();

        var rawCert = hsmSigningIssuance.getCertificate(eccKeyV0);
        var cert = X509CertUtils.parse(rawCert);
        var sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(cert);
        sig.update(DATA_TO_SIGN);
        var derSignature = ECDSA.transcodeSignatureToDER(signature);
        var sigValid = sig.verify(derSignature);
        assertThat(sigValid).isTrue();
    }

    @Test
    void signWithUnknownKey() {
        var unknownKeyId = new VersionedKeyID(eccKey, 42);
        assertThatExceptionOfType(KeyNotFoundException.class).isThrownBy(() -> hsmSigningIssuance.sign(unknownKeyId, DATA_TO_SIGN));
    }

    @Test
    void findCertificate() {
        var rawCert = hsmSigningIssuance.getCertificate(eccKeyV0);
        assertThat(rawCert).isNotEmpty();
        var cert = X509CertUtils.parse(rawCert);
        assertThat(cert.getSigAlgName()).isEqualTo("SHA256withECDSA");
    }

    @Test
    void findCertificateFromUnknownKey() {
        var unknownKeyId = new VersionedKeyID(eccKey, 42);
        assertThatExceptionOfType(KeyNotFoundException.class).isThrownBy(() -> hsmSigningIssuance.getCertificate(unknownKeyId));
    }
}
