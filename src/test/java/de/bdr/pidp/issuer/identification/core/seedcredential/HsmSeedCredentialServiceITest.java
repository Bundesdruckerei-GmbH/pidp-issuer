/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMSigningService;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import de.bdr.pidp.issuer.identification.port.out.EncryptionKeyPortOut;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.TransitKeyType;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;

import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SpringBootTest(properties = {"pidi.identification.create-seed-credential=true","hsm.enabled=true"})
class HsmSeedCredentialServiceITest {

    @Autowired
    private SeedCredentialService service;

    @Autowired
    private IdentificationConfiguration identificationConfiguration;

    @Autowired
    private VaultTemplate vaultTemplate;

    @MockitoSpyBean
    private HSMSigningService hsmSigningIdentification;

    @MockitoSpyBean
    private EncryptionKeyPortOut encKeyProvider;

    @AfterEach
    void tearDown() {
        reset(encKeyProvider);
        reset(hsmSigningIdentification);
    }

    @Test
    void seedCredentialSuccessfullyCreated() throws ParseException, JOSEException {
        var seedCredentialData = service.createSeedCredential(TEST_IDENTITY_DATA);
        assertThat(seedCredentialData.seedCredential()).isNotNull();

        JWEObject jwe = JWEObject.parse(seedCredentialData.seedCredential());
        Key kek = fetchEncKey();
        SecretKey secretKey = assertThat(kek).asInstanceOf(InstanceOfAssertFactories.type(SecretKey.class)).actual();

        AESDecrypter decrypter = new AESDecrypter(secretKey);
        jwe.decrypt(decrypter);
        SignedJWT jwt = jwe.getPayload().toSignedJWT();

        var rawCert = hsmSigningIdentification.getCertificate(VersionedKeyID.parse(jwt.getHeader().getKeyID()));
        X509Certificate cert = X509CertUtils.parse(rawCert);
        ECKey key = ECKey.parse(cert);
        ECDSAVerifier verifier = new ECDSAVerifier(key);

        assertThat(verifier.verify(jwt.getHeader(), jwt.getSigningInput(), jwt.getSignature())).isTrue();
    }

    @Test
    void seedCredentialSuccessfullyVerified() {
        var seedCredentialData = service.createSeedCredential(TEST_IDENTITY_DATA);
        assertThat(seedCredentialData).isNotNull();

        SeedCredentialData verifiedSeedCredentialData = service.verifySeedCredentialAndGetData(seedCredentialData.seedCredential());
        assertThat(verifiedSeedCredentialData).isNotNull();
        assertThat(verifiedSeedCredentialData.identityData()).isNotNull();
        assertThat(verifiedSeedCredentialData.identityData().familyNames()).isEqualTo(TEST_IDENTITY_DATA.familyNames());
    }

    @Test
    void certificateCached() {
        var _ = service.createSeedCredential(TEST_IDENTITY_DATA);
        var _ = service.createSeedCredential(TEST_IDENTITY_DATA);

        verify(hsmSigningIdentification, times(2))
            .getLatestVersionKeyAttributes(argThat(kid -> kid.value().equals(identificationConfiguration.getSeedSigAliasHsm())));
        verify(hsmSigningIdentification, atMost(1))
            .getCertificate(argThat(kid -> kid.keyID().value().equals(identificationConfiguration.getSeedSigAliasHsm())));
    }

    private Key fetchEncKey() {
        var rawKey = vaultTemplate.opsForTransit(identificationConfiguration.getKms().getTransitPath()).exportKey(identificationConfiguration.getSeedEncAlias(), TransitKeyType.ENCRYPTION_KEY);
        var keyByVersion = Objects.requireNonNull(rawKey).getKeys().get("1");
        var decodedKey = Base64.getDecoder().decode(keyByVersion);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
