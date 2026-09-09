/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.config.MetadataSignerConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.core.signer.MetadataSigner;
import de.bdr.pidp.issuer.issuance.core.signer.PKCS12CredentialSigner;
import de.bdr.pidp.issuer.issuance.openid4vci.in.model.SdJwtVcMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.service.MetadataService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static de.bdr.pidp.issuer.base.FileResourceHelper.getFileInputStream;
import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static de.bdr.pidp.issuer.issuance.ConfigTestData.METADATA_SIGNER_CONFIG;
import static de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata.ISSUANCE_METADATA;
import static de.bdr.pidp.issuer.issuance.openid4vci.in.MetadataController.OPENIDVCI_ISSUER_METADATA_JWT_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MetadataControllerTest {

    private static JWK testJwk;

    private final MetadataSignerConfiguration metadataConfig = METADATA_SIGNER_CONFIG;
    private final FileResourceHelper fileResourceHelper = new FileResourceHelper();

    @Spy
    private CredentialIssuerMetadata credentialMetadata = ISSUANCE_METADATA;
    @Spy
    private ReadOnlyAuthMetadata metadata = MetaTestData.AUTH_METADATA;
    @Mock
    private MetadataService metadataService;
    @Mock
    private MetadataSigner metadataSigner;

    @InjectMocks
    private MetadataController metadataController;

    @BeforeAll
    static void setUpAll() throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, JOSEException {
        var pkcs12Signer = new PKCS12CredentialSigner(
            Objects.requireNonNull(getFileInputStream(ISSUANCE_CONFIG.getSignerPath())),
            ISSUANCE_CONFIG.getSignerPassword());
        testJwk = JWK.parse(pkcs12Signer.getCertificateChain().getFirst());
    }

    @Test
    void getSdJwtVcMetadataEmptyKeyStore() {
        when(metadataService.getJWKs()).thenReturn(Collections.emptyList());

        var e = assertThrows(PidServerException.class, () -> metadataController.getJwtVcIssuerMetadataJSON());
        assertThat(e.getMessage()).isEqualTo("No certificate found");
    }

    @Test
    void getSdJwtVcMetadataKeyStoreWithTwoCertificates() {
        when(metadataService.getJWKs()).thenReturn(List.of(testJwk, testJwk));

        SdJwtVcMetadata response = metadataController.getJwtVcIssuerMetadataJSON();
        assertThat(response).isNotNull();
        assertThat(response.issuer()).isEqualTo(credentialMetadata.credentialIssuer().getValue());
        assertThat(response.jwks().keys()).hasSize(2);
    }

    @Test
    void getCredentialMetadata() {
        var response = metadataController.getCredentialIssuerMetadataJSON();
        var keyStorageTypes = """
                            "key_storage":[
                            "iso_18045_high"
                            ],
                            "user_authentication":[
                            "iso_18045_high"
                            ]
                            """;
        assertThat(response.getBody()).isNotNull().containsIgnoringNewLines(keyStorageTypes);
    }

    @Test
    void getCredentialMetadataJwt() throws ParseException, KeyStoreException, JOSEException {
        var tmpMetadataSigner = new MetadataSigner(fileResourceHelper, metadataConfig);
        when(metadataSigner.getSignerKey()).thenReturn(tmpMetadataSigner.getSignerKey());
        when(metadataSigner.getSigner()).thenReturn(tmpMetadataSigner.getSigner());
        when(metadataSigner.getAccessCertificate()).thenReturn(tmpMetadataSigner.getAccessCertificate());
        var response = metadataController.getCredentialIssuerMetadataJWT();
        assertThat(response).isNotNull();
        SignedJWT jwt = SignedJWT.parse(response);
        assertThat(jwt.getHeader().getType()).isEqualTo(new JOSEObjectType(OPENIDVCI_ISSUER_METADATA_JWT_TYPE));
        assertThat(jwt.verify(getJwsVerifier())).isTrue();
    }

    private JWSVerifier getJwsVerifier() throws KeyStoreException, JOSEException {
        var keystore = fileResourceHelper.readKeyStore(metadataConfig.getSignerPath(), metadataConfig.getSignerPassword());
        var signerKey = ECKey.load(keystore, metadataConfig.getSignerAlias(), metadataConfig.getSignerPassword().toCharArray());
        return new ECDSAVerifier(signerKey);
    }
}
