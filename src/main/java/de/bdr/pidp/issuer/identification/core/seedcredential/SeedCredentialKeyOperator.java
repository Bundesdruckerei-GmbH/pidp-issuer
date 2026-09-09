/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.jwk.LazyJWKSource;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.identification.port.out.EncryptionKeyPortOut;
import de.bdr.pidp.issuer.identification.port.out.SeedCredentialSignerPortOut;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@NullMarked
@Component
public class SeedCredentialKeyOperator {

    private static final String CIPHER = "AES";
    private static final int KEY_SIZE = 256;

    private static final JOSEObjectType JWT_TYPE = new JOSEObjectType("seed-credential+jwt");

    private final String seedPassword;
    private final KeyID seedEncAlias;
    private final KeyID seedSigAlias;
    private final JWTProcessor<?> jwtProcessor;
    private final EncryptionKeyPortOut encKeyProvider;
    @Nullable
    private final SeedCredentialSignerPortOut signatureProvider;
    private final Map<Integer, SecretKey> keyEncryptionKeys = new HashMap<>();

    @Nullable
    private final KeyStore keystore;

    public SeedCredentialKeyOperator(IdentificationConfiguration configuration, FileResourceHelper helper, EncryptionKeyPortOut encKeyProvider, @Nullable SeedCredentialSignerPortOut signatureProvider) {
        this.seedPassword = configuration.getSeedPassword();
        this.seedEncAlias = new KeyID(configuration.getSeedEncAlias());
        this.seedSigAlias = new KeyID(configuration.getSeedSigAlias());
        this.encKeyProvider = encKeyProvider;
        this.signatureProvider = signatureProvider;
        this.jwtProcessor = buildJWTProcessor(
            configuration.getCredentialIssuerIdentifier(),
            (int) configuration.getTimeTolerance().toSeconds()
        );
        var seedPath = configuration.getSeedPath();
        this.keystore = (signatureProvider == null)
            ? helper.readKeyStore(seedPath, seedPassword)
            : null;
    }

    public SignedJWT signSeedCredential(JWTClaimsSet seedClaims) {
        if (signatureProvider != null) {
            var context = signatureProvider.signingContext();

            JWSHeader header = new JWSHeader.Builder(context.algorithm())
                .type(JWT_TYPE)
                .keyID(context.keyID())
                .x509CertSHA256Thumbprint(X509CertUtils.computeSHA256Thumbprint(context.cert()))
                .build();
            var jws = new SignedJWT(header, seedClaims);
            var signer = context.signer();
            try {
                jws.sign(signer);
                return jws;
            } catch (JOSEException e) {
                throw new SeedException("could not sign the seed PID", e);
            }
        } else {
            try {
                ECKey signerKey = getSignerKey();
                if (signerKey == null) {
                    throw new SeedException("No key pair found for signing!");
                }
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384)
                    .type(JWT_TYPE)
                    .keyID(seedSigAlias.value())
                    .x509CertSHA256Thumbprint(signerKey.getX509CertSHA256Thumbprint())
                    .build();
                var jws = new SignedJWT(header, seedClaims);
                var signer = new ECDSASigner(signerKey);
                jws.sign(signer);
                return jws;
            } catch (KeyStoreException | JOSEException e) {
                throw new SeedException("could not sign the seed PID", e);
            }
        }
    }

    public JWEObject encrypt(SignedJWT seedCredentialJWT) {
        var kid = getLatestKeyID();
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A256KW, EncryptionMethod.A256GCM)
            .contentType("JWT") // required to indicate nested JWT
            .type(JWT_TYPE)
            .keyID(kid.toString())
            .build();
        JWEObject jwe = new JWEObject(header, new Payload(seedCredentialJWT));

        try {
            var encrypter = getEncrypter(kid);
            jwe.encrypt(encrypter);
            return jwe;
        } catch (JOSEException | NoSuchAlgorithmException e) {
            throw new SeedException("could not encrypt the signed seed PID", e);
        }
    }

    public JWTClaimsSet decryptAndVerify(EncryptedJWT seedCredentialJWE) {
        try {
            return jwtProcessor.process(seedCredentialJWE, null);
        } catch (BadJOSEException e) {
            throw new SeedException("Seed Credential is invalid: " + e.getMessage(), e);
        } catch (JOSEException | KeyNotFoundException e) {
            throw new SeedException("Seed Credential is invalid", e);
        }
    }

    private JWTProcessor<?> buildJWTProcessor(String issuerIdentifier, int clockSkew) {
        var processor = new DefaultJWTProcessor<>();
        processor.setJWETypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JWT_TYPE));
        // KeyID gets string compared with aliases in JWKSet, so no sanitizing/validation is necessary here
        processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(JWEAlgorithm.A256KW, EncryptionMethod.A256GCM, new LazyJWKSource<>(this::getJWKSetByKMS)));
        processor.setJWEDecrypterFactory(new DefaultJWEDecrypterFactory());

        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JWT_TYPE));
        if (signatureProvider != null) {
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.Family.EC, signatureProvider.jwkSource()));
        } else {
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.Family.EC, new LazyJWKSource<>(this::getJWKSet)));
        }
        processor.setJWTClaimsSetVerifier(new SeedCredentialClaimsVerifier(issuerIdentifier, clockSkew));

        return processor;
    }

    private @Nullable ECKey getSignerKey() throws KeyStoreException, JOSEException {
        return ECKey.load(getRequiredKeystore(), seedSigAlias.value(), seedPassword.toCharArray());
    }

    private JWKSet getJWKSet(Set<String> jwsKIDs) {
        try {
            return JWKSet.load(getRequiredKeystore(), _ -> seedPassword.toCharArray());
        } catch (KeyStoreException e) {
            throw new SeedException("could not get JWKSet", e);
        }
    }

    private JWKSet getJWKSetByKMS(Set<String> jweKIDs) {
        var jweKID = jweKIDs.stream().findFirst().orElseThrow(() -> new SeedException("Could not find keyID in Seed Credential"));
        var kid = VersionedKeyID.parse(jweKID);
        return encKeyProvider.fetchEncryptionKeySet(kid);
    }

    private VersionedKeyID getLatestKeyID() {
        var latest = encKeyProvider.getLatestVersion(seedEncAlias);
        return new VersionedKeyID(seedEncAlias, latest);
    }

    private AESEncrypter getEncrypter(VersionedKeyID kid) throws JOSEException, NoSuchAlgorithmException {
        SecretKey kek;
        if (keyEncryptionKeys.containsKey(kid.version())) {
            kek = keyEncryptionKeys.get(kid.version());
        } else {
            kek = encKeyProvider.fetchEncryptionKey(kid);
            keyEncryptionKeys.put(kid.version(), kek);
        }
        return new AESEncrypter(kek, getKeyFromKeyGenerator(CIPHER, KEY_SIZE));
    }

    private SecretKey getKeyFromKeyGenerator(String cipher, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(cipher);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private KeyStore getRequiredKeystore() {
        if (this.keystore == null) {
            throw new PidServerException("Keystore is not available when signatureProvider is used");
        }
        return this.keystore;
    }
}
