/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.hsm;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import de.bdr.pidp.issuer.issuance.core.signer.Algorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "hsm.enabled=true")
class HSMCredentialSignerAdapterTest {

    @Autowired
    private HSMCredentialSignerAdapter subject;

    @Test
    void sign() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, JOSEException {
        var value = "SomeTestValue";

        var sig = subject.sign(value.getBytes());
        var derSig = ECDSA.transcodeSignatureToDER(sig);

        var leafCert = subject.getCertificateChain().getFirst();
        Signature signature = Signature.getInstance("SHA256WithECDSA");
        signature.initVerify(leafCert);
        signature.update(value.getBytes());
        assertThat(signature.verify(derSig)).isTrue();
    }

    @Test
    void getCertKeyMaterial() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        var chain = subject.getCertificateChain();

        assertThat(chain).hasSize(2);
        X509Certificate leafCert = chain.getFirst();
        assertThat(leafCert.getNotBefore()).isBeforeOrEqualTo(Instant.now());
        assertThat(leafCert.getNotAfter()).isAfterOrEqualTo(Instant.now());

        assertThat(leafCert.getKeyUsage()[0]).isTrue();
        assertThat(leafCert.getPublicKey()).isInstanceOfAny(ECPublicKey.class);

        X509Certificate rootCA = chain.getLast();
        leafCert.verify(rootCA.getPublicKey());
    }

    @Test
    void getAlgorithm() {
        var alg = subject.getAlgorithm();

        assertThat(alg).isEqualTo(Algorithm.ES256);
    }
}
