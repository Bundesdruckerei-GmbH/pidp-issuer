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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.identification.port.out.EncryptionKeyPortOut;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.TransitKeyType;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;

import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SpringBootTest(properties = {"pidi.identification.create-seed-credential=true","hsm.enabled=false"})
class SeedCredentialServiceITest {

    @Autowired
    private SeedCredentialService service;

    @Autowired
    private FileResourceHelper fileResourceHelper;

    @Autowired
    private SeedCredentialKeyOperator seedCredentialKeyOperator;

    @Autowired
    private IdentificationConfiguration identificationConfiguration;

    @Autowired
    private VaultTemplate vaultTemplate;

    @MockitoSpyBean
    private EncryptionKeyPortOut encKeyProvider;

    @AfterEach
    void tearDown() {
        reset(encKeyProvider);
    }

    @Test
    void seedCredentialSuccessfullyCreated() throws ParseException, KeyStoreException, JOSEException {
        var seedCredentialData = service.createSeedCredential(TEST_IDENTITY_DATA);

        String seedPassword = identificationConfiguration.getSeedPassword();
        KeyStore keyStore = fileResourceHelper.readKeyStore(identificationConfiguration.getSeedPath(), seedPassword);

        JWEObject jwe = JWEObject.parse(seedCredentialData.seedCredential());
        Key kek = fetchEncKey();
        SecretKey secretKey = assertThat(kek).asInstanceOf(InstanceOfAssertFactories.type(SecretKey.class)).actual();

        AESDecrypter decrypter = new AESDecrypter(secretKey);
        jwe.decrypt(decrypter);
        SignedJWT jwt = jwe.getPayload().toSignedJWT();

        ECKey key = ECKey.load(keyStore, identificationConfiguration.getSeedSigAlias(), seedPassword.toCharArray());
        ECDSAVerifier verifier = new ECDSAVerifier(key.toECPublicKey());

        assertThat(verifier.verify(jwt.getHeader(), jwt.getSigningInput(), jwt.getSignature())).isTrue();
    }

    @Test
    void encryptionKeyCached() {
        var seedCredentialData1 = service.createSeedCredential(TEST_IDENTITY_DATA);
        var seedCredentialData2 = service.createSeedCredential(TEST_IDENTITY_DATA);

        var _ = service.verifySeedCredentialAndGetData(seedCredentialData1.seedCredential());
        var _ = service.verifySeedCredentialAndGetData(seedCredentialData2.seedCredential());

        verify(encKeyProvider, times(2)).getLatestVersion(any());
        verify(encKeyProvider, atMost(1)).fetchEncryptionKey(any());
        verify(encKeyProvider, atMost(1)).fetchEncryptionKeySet(any());
    }

    @Test
    void incorrectAliasShouldResultInAnException() {
        var seedEncAlias = identificationConfiguration.getSeedEncAlias();
        try {
            ReflectionTestUtils.setField(seedCredentialKeyOperator, "seedEncAlias", new KeyID("false_" + seedEncAlias));
            assertThatThrownBy(() -> service.createSeedCredential(TEST_IDENTITY_DATA)).isInstanceOf(KeyNotFoundException.class);
        } finally {
            ReflectionTestUtils.setField(seedCredentialKeyOperator, "seedEncAlias", new KeyID(seedEncAlias));
        }
    }

    @Test
    void successVerifyAndGetSeedCredentialData() {
        var seedCredentialData = service.createSeedCredential(TEST_IDENTITY_DATA);

        var result = service.verifySeedCredentialAndGetData(seedCredentialData.seedCredential());

        assertThat(result.identityData()).isNotNull();
        assertThat(result.identityData().givenNames()).isEqualTo(TEST_IDENTITY_DATA.givenNames());
        assertThat(result.identityData().familyNames()).isEqualTo(TEST_IDENTITY_DATA.familyNames());
        assertThat(result.identityData().birthName()).isEqualTo(TEST_IDENTITY_DATA.birthName());
    }

    @Test
    void couldNotParseSeedCredential() {
        var seedCredential = "Houston, wir haben ein Problem";

        assertThatThrownBy(() -> service.verifySeedCredentialAndGetData(seedCredential))
            .isInstanceOf(SeedException.class);
    }

    @Test
    void couldNotValidateSeedCredentialClaims() throws ParseException {
        var mapper = ReflectionTestUtils.getField(service, "mapper");

        var mock = mock(EidDataMapper.class);
        doThrow(ParseException.class).when(mock).map(any(JWTClaimsSet.class));
        var seedCredentialData = service.createSeedCredential(TEST_IDENTITY_DATA);

        try {
            ReflectionTestUtils.setField(service, "mapper", mock);
            assertThatThrownBy(() -> service.verifySeedCredentialAndGetData(seedCredentialData.seedCredential()))
                .isInstanceOf(SeedException.class);
        } finally {
            ReflectionTestUtils.setField(service, "mapper", mapper);
        }

    }

    private Key fetchEncKey() {
        var rawKey = vaultTemplate.opsForTransit(identificationConfiguration.getKms().getTransitPath()).exportKey(identificationConfiguration.getSeedEncAlias(), TransitKeyType.ENCRYPTION_KEY);
        var keyByVersion = Objects.requireNonNull(rawKey).getKeys().get("1");
        var decodedKey = Base64.getDecoder().decode(keyByVersion);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
