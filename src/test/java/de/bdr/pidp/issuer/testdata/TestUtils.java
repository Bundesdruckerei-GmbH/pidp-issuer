/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static java.util.Optional.ofNullable;

@Slf4j
public class TestUtils {
    private static final String CERTIFICATES_BASE_PATH = "/certificates";
    // misc
    public static final String NONCE_REGEX = "[a-zA-Z0-9]{44}";
    public static final String ID_REGEX = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    public static final String ISSUER_IDENTIFIER_AUDIENCE = TestConfig.pidiBaseUrl();
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final String DPOP_SCHEME = "DPoP";

    // JWT Types
    public static final JOSEObjectType JWT_PROOF_TYPE = new JOSEObjectType("openid4vci-proof+jwt");
    public static final JOSEObjectType CLIENT_ATTESTATION_TYPE = new JOSEObjectType("oauth-client-attestation+jwt");
    public static final JOSEObjectType CLIENT_ATTESTATION_POP_TYPE = new JOSEObjectType("oauth-client-attestation-pop+jwt");

    // client / wallet
    public static final String CLIENT_PRIVATE_KEY_PATH = CERTIFICATES_BASE_PATH + "/pidp-client-key-attestation-wia-wte-test-privkey.pem";
    public static final String CLIENT_CERTIFICATE_PATH_SELF_SIGNED = CERTIFICATES_BASE_PATH + "/pidp-client-attestation-wia-test.crt";
    public static final String CLIENT_CERTIFICATE_PATH_CHAIN = CERTIFICATES_BASE_PATH + "/pidp-client-attestation-wia-test-fullchain.crt";
    public static final String CLIENT_CERTIFICATE_PATH_TEST_RSA = CERTIFICATES_BASE_PATH + "/pidp-test.crt";
    public static final PrivateKey CLIENT_PRIVATE_KEY = readPrivateKey(CLIENT_PRIVATE_KEY_PATH, "EC");
    public static final List<X509Certificate> CLIENT_CERTIFICATE_SELF_SIGNED = readClientCertificate(CLIENT_CERTIFICATE_PATH_SELF_SIGNED);
    public static final List<X509Certificate> CLIENT_CERTIFICATE_CHAIN = readClientCertificate(CLIENT_CERTIFICATE_PATH_CHAIN);
    public static final List<X509Certificate> CLIENT_CERTIFICATE_TEST_RSA = readClientCertificate(CLIENT_CERTIFICATE_PATH_TEST_RSA);
    public static final List<com.nimbusds.jose.util.Base64> CLIENT_CERTIFICATE_SELF_SIGNED_B64 = readClientCertificateB64(CLIENT_CERTIFICATE_PATH_SELF_SIGNED);
    public static final JWK CLIENT_PUBLIC_KEY;

    public static final String CLIENT_SUB_PRIVATE_KEY_PATH = CERTIFICATES_BASE_PATH + "/pidp-client-key-attestation-wia-wte-test-privkey.pem";
    public static final String CLIENT_SUB_CERTIFICATE_PATH = CERTIFICATES_BASE_PATH + "/pidp-client-key-attestation-wia-wte-test-subca.crt";
    public static final PrivateKey CLIENT_SUB_CLIENT_PRIVATE_KEY = readPrivateKey(CLIENT_SUB_PRIVATE_KEY_PATH, "EC");
    public static final List<X509Certificate> CLIENT_SUB_CLIENT_CERTIFICATE = readClientCertificate(CLIENT_SUB_CERTIFICATE_PATH);
    public static final List<com.nimbusds.jose.util.Base64> CLIENT_SUB_CLIENT_CERTIFICATE_B64 = readClientCertificateB64(CLIENT_SUB_CERTIFICATE_PATH);

    public static final String CLIENT_EXPIRED_CERTIFICATE_PATH = CERTIFICATES_BASE_PATH + "/pidp-test-expired.crt";
    public static final List<X509Certificate> CLIENT_EXPIRED_CLIENT_CERTIFICATE = readClientCertificate(CLIENT_EXPIRED_CERTIFICATE_PATH);

    public static final String CLIENT_UNKNOWN_CERTIFICATE_PATH = CERTIFICATES_BASE_PATH + "/pidp-invalid-signature.crt";
    public static final List<X509Certificate> CLIENT_UNKNOWN_CERTIFICATE = readClientCertificate(CLIENT_UNKNOWN_CERTIFICATE_PATH);

    public static final Set<X509Certificate> CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED = Set.of(CLIENT_CERTIFICATE_SELF_SIGNED.getLast());
    public static final Set<X509Certificate> CLIENT_ATTESTATION_TRUST_ANCHOR_CHAIN_LEAF = Set.of(CLIENT_CERTIFICATE_CHAIN.getFirst());
    public static final Set<X509Certificate> CLIENT_ATTESTATION_TRUST_ANCHOR_CHAIN_CA = Set.of(CLIENT_CERTIFICATE_CHAIN.getLast());
    public static final Set<X509Certificate> CLIENT_ATTESTATION_TRUST_ANCHORS = Set.of(CLIENT_CERTIFICATE_CHAIN.getLast(), CLIENT_CERTIFICATE_SELF_SIGNED.getLast());

    public static final StatusListRef CLIENT_ATTESTATION_STATUS_LIST_REF = new StatusListRef(URI.create("http://bdr.de/pidp/dummy-status-list"), 10);

    // device / client instance
    public static final ECKey DEVICE_KEY_PAIR = generateEcKey();
    public static final JWK DEVICE_PUBLIC_KEY = DEVICE_KEY_PAIR.toPublicJWK();
    public static final Base64URL DEVICE_JWK_THUMBPRINT;

    // key attestation
    public static final JOSEObjectType KEY_ATTESTATION_TYPE = new JOSEObjectType("key-attestation+jwt");
    public static final String KEY_ATTESTATION_PRIVATE_KEY_PATH = CERTIFICATES_BASE_PATH + "/pidp-client-key-attestation-wia-wte-test-privkey.pem";
    public static final String KEY_ATTESTATION_CERTIFICATE_PATH = CERTIFICATES_BASE_PATH + "/pidp-key-attestation-wte-test.crt";
    public static final String KEY_ATTESTATION_TEST_CERTIFICATE_PATH = CERTIFICATES_BASE_PATH + "/pidp-key-attestation-wte-test-cert.crt";
    public static final PrivateKey KEY_ATTESTATION_PRIVATE_KEY = readPrivateKey(KEY_ATTESTATION_PRIVATE_KEY_PATH, "EC");
    public static final List<X509Certificate> KEY_ATTESTATION_CERTIFICATE = readClientCertificate(KEY_ATTESTATION_CERTIFICATE_PATH);
    public static final List<X509Certificate> KEY_ATTESTATION_TEST_CERTIFICATE = readClientCertificate(KEY_ATTESTATION_TEST_CERTIFICATE_PATH);
    public static final List<com.nimbusds.jose.util.Base64> KEY_ATTESTATION_CERTIFICATE_B64 = readClientCertificateB64(KEY_ATTESTATION_CERTIFICATE_PATH);
    public static final List<JWK> ATTESTED_KEYS = List.of(generateEcKey());
    public static final List<JWK> ATTESTED_KEYS_DPOP = List.of(DEVICE_PUBLIC_KEY);

    public static final Set<X509Certificate> KEY_ATTESTATION_TRUST_ANCHOR = Set.of(KEY_ATTESTATION_CERTIFICATE.getLast());
    public static final Set<X509Certificate> KEY_ATTESTATION_TRUST_ANCHORS = Set.of(KEY_ATTESTATION_CERTIFICATE.getLast(), KEY_ATTESTATION_TEST_CERTIFICATE.getLast());

    // request encryption
    public static final ECKey REQUEST_ENCRYPTION_KAK = generateECDHEncryptionKey();
    public static final JWK REQUEST_ENCRYPTION_PUB = REQUEST_ENCRYPTION_KAK.toPublicJWK();

    // relying party
    public static final ECKey RELYING_PARTY_KEY_PAIR = generateEcKey();
    public static final JWK RELYING_PARTY_PUBLIC_KEY = RELYING_PARTY_KEY_PAIR.toPublicJWK();

    // unknown / invalid
    public static final ECKey DIFFERENT_KEY_PAIR = generateEcKey();

    static {
        try {
            CLIENT_PUBLIC_KEY = JWK.parse(CLIENT_CERTIFICATE_SELF_SIGNED.getFirst());
            DEVICE_JWK_THUMBPRINT = DEVICE_PUBLIC_KEY.computeThumbprint();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    // -------------------------------- Miscellaneous ------------------------------------------------------------------

    public static ECKey generateEcKey() {
        try {
            int nextedInt = SECURE_RANDOM.nextInt();
            log.debug("~~~~ KeyGen, random int: {}, algo: {}, provider: {}", nextedInt, SECURE_RANDOM.getAlgorithm(), SECURE_RANDOM.getProvider());
            return new ECKeyGenerator(Curve.P_256).secureRandom(SECURE_RANDOM)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(RandomUtil.randomString())
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECKey generateECDHEncryptionKey() {
        try {
            int nextedInt = SECURE_RANDOM.nextInt();
            log.debug("~~~~ KeyGen, random int: {}, algo: {}, provider: {}", nextedInt, SECURE_RANDOM.getAlgorithm(), SECURE_RANDOM.getProvider());
            return new ECKeyGenerator(Curve.P_256).secureRandom(SECURE_RANDOM)
                .keyUse(KeyUse.ENCRYPTION)
                .keyID(RandomUtil.randomString())
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECKey generateEcKey384() {
        try {
            int nextedInt = SECURE_RANDOM.nextInt();
            log.debug("~~~~ KeyGen, random int: {}, algo: {}, provider: {}", nextedInt, SECURE_RANDOM.getAlgorithm(), SECURE_RANDOM.getProvider());
            return new ECKeyGenerator(Curve.P_384).secureRandom(SECURE_RANDOM)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(RandomUtil.randomString())
                .algorithm(JWSAlgorithm.ES384)
                .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public static SignedJWT buildJWT(JWTClaimsSet claims, JOSEObjectType type, ECKey keyPair) {
        return buildJWT(claims, type, keyPair, keyPair.toPublicJWK());
    }

    public static SignedJWT buildJWT(JWTClaimsSet claims, JOSEObjectType type, ECKey keyPair, JWK headerJwk) {
        var algorithm = JWSAlgorithm.parse(keyPair.getAlgorithm().getName());
        var header = new JWSHeader.Builder(algorithm)
            .jwk(headerJwk)
            .type(type)
            .build();
        var signedJWT = new SignedJWT(header, claims);
        try {
            var signer = new ECDSASigner(keyPair.toECKey());
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    public static SignedJWT buildX5CJWT(JWTClaimsSet claims, JOSEObjectType type, ECKey keyPair, List<com.nimbusds.jose.util.Base64> jwkWithCertChain) {
        var algorithm = JWSAlgorithm.parse(keyPair.getAlgorithm().getName());
        var header = new JWSHeader.Builder(algorithm)
            .x509CertChain(jwkWithCertChain)
            .type(type)
            .build();
        var signedJWT = new SignedJWT(header, claims);
        try {
            var signer = new ECDSASigner(keyPair.toECKey());
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    public static SignedJWT buildX5CJWT(JWTClaimsSet claims, JOSEObjectType type, ECPrivateKey privateKey, List<com.nimbusds.jose.util.Base64> jwkWithCertChain) {
        var algorithm = JWSAlgorithm.ES256;
        var header = new JWSHeader.Builder(algorithm)
            .x509CertChain(jwkWithCertChain)
            .type(type)
            .build();
        var signedJWT = new SignedJWT(header, claims);
        try {
            var signer = new ECDSASigner(privateKey);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    public static SignedJWT buildJWT(JWTClaimsSet claims, JOSEObjectType type, PrivateKey privateKey, JWK publicKey) {
        var header = new JWSHeader.Builder(JWSAlgorithm.PS256)
            .jwk(publicKey)
            .type(type)
            .build();
        var signedJWT = new SignedJWT(header, claims);
        try {
            var signer = new RSASSASigner(privateKey);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    public static SignedJWT buildJWT(JWTClaimsSet claims, JOSEObjectType type, ECPrivateKey privateKey, JWK publicKey) {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .jwk(publicKey)
            .type(type)
            .build();
        var signedJWT = new SignedJWT(header, claims);
        try {
            var signer = new ECDSASigner(privateKey);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    // -------------------------------- Credential Request -------------------------------------------------------------

    public static JWEObject generateEncryptedJWT(ECKey keyAgreementKey, String payload) {
        var header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .keyID(keyAgreementKey.getKeyID())
            .build();
        var payloadObj = new Payload(payload);
        var jwe = new JWEObject(header, payloadObj);
        ECDHEncrypter encrypter;
        try {
            encrypter = new ECDHEncrypter(keyAgreementKey.toECPublicKey(), null);
            jwe.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwe;
    }

    // -------------------------------- Credential Request POP/Proof ---------------------------------------------------

    public static SignedJWT buildProofJwt(String issuer, String audience, Instant issueTime, String nonce) {
        return buildProofJwt(JWT_PROOF_TYPE, issuer, audience, issueTime, nonce);
    }

    public static SignedJWT buildProofJwt(JOSEObjectType type, String issuer, String audience, Instant issueTime, String nonce) {
        var claims = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .issueTime(ofNullable(issueTime).map(Date::from).orElse(null))
            .claim("nonce", nonce)
            .build();

        return buildJWT(claims, type, RELYING_PARTY_KEY_PAIR);
    }

    /**
     * @return proof with different public key in header
     */
    public static SignedJWT buildInvalidProofJwt(ECKey deviceKeyPair, String issuer, String audience, Instant issueTime, String nonce) {
        var claims = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .issueTime(Date.from(issueTime))
            .claim("nonce", nonce)
            .build();

        return buildJWT(claims, JWT_PROOF_TYPE, deviceKeyPair, DIFFERENT_KEY_PAIR.toPublicJWK());
    }

    // -------------------------------- Client Attestation -------------------------------------------------------------
    public static Map<String, List<String>> getClientAttestationHeaders() {
        return Map.of("oauth-client-attestation", List.of(getValidClientAttestationJwt().serialize()),
            "oauth-client-attestation-pop", List.of(getValidClientAttestationPopJwt().serialize()));
    }

    public static JWTClaimsSet.Builder getClientAttestationClaimsBuilderWithDefaults() {
        var now = Instant.now();
        var status = CLIENT_ATTESTATION_STATUS_LIST_REF.toJWTClaim();
        return new JWTClaimsSet.Builder()
            .issuer("http://unique.wallet.identifier")
            .subject(ClientIds.validClientIdForSelfSigned().toString())
            .expirationTime(Date.from(now.plusSeconds(30L)))
            .notBeforeTime(Date.from(now))
            .issueTime(Date.from(now))
            .claim("cnf", Map.of("jwk", getClientInstanceKeyMap()))
            .claim(status.getKey(), status.getValue());
    }

    public static SignedJWT getClientAttestationJwt(JWTClaimsSet claims, JOSEObjectType type) {
        return buildX5CJWT(claims, type, (ECPrivateKey) CLIENT_PRIVATE_KEY, CLIENT_CERTIFICATE_SELF_SIGNED_B64);
    }

    public static SignedJWT getValidClientAttestationJwt() {
        var claims = getClientAttestationClaimsBuilderWithDefaults().build();
        return getClientAttestationJwt(claims, CLIENT_ATTESTATION_TYPE);
    }

    public static SignedJWT getValidClientAttestationJwtSubSigned() {
        var claims = getClientAttestationClaimsBuilderWithDefaults().build();
        return buildX5CJWT(claims, CLIENT_ATTESTATION_TYPE, (ECPrivateKey) CLIENT_SUB_CLIENT_PRIVATE_KEY, CLIENT_SUB_CLIENT_CERTIFICATE_B64);
    }

    /**
     * @return client attestation signed by device key instead of client key
     */
    public static SignedJWT getInvalidClientAttestationJwt() {
        var claims = getClientAttestationClaimsBuilderWithDefaults().build();
        return buildX5CJWT(claims, CLIENT_ATTESTATION_TYPE, DEVICE_KEY_PAIR, CLIENT_CERTIFICATE_SELF_SIGNED_B64);
    }

    public static JWTClaimsSet.Builder getClientAttestationPoPClaimsBuilderWithDefaults(String challenge) {
        var now = Instant.now();
        var builder = new JWTClaimsSet.Builder()
            .issuer(ClientIds.validClientIdForSelfSigned().toString())
            .audience(ISSUER_IDENTIFIER_AUDIENCE)
            .issueTime(Date.from(now))
            .jwtID("test")
            .notBeforeTime(Date.from(now));
        if (challenge != null) {
            builder.claim("challenge", challenge);
        }
        return builder;
    }

    public static SignedJWT getValidClientAttestationPopJwt() {
        var claims = getClientAttestationPoPClaimsBuilderWithDefaults(null).build();
        return buildJWT(claims, CLIENT_ATTESTATION_POP_TYPE, DEVICE_KEY_PAIR);
    }

    public static SignedJWT getValidClientAttestationPopJwt(String challenge) {
        var claims = getClientAttestationPoPClaimsBuilderWithDefaults(challenge).build();
        return buildJWT(claims, CLIENT_ATTESTATION_POP_TYPE, DEVICE_KEY_PAIR);
    }

    public static SignedJWT getClientAttestationPoPJwt(JWTClaimsSet claims, JOSEObjectType type) {
        return buildJWT(claims, type, DEVICE_KEY_PAIR);
    }

    public static Map<String, Object> getClientInstanceKeyMap() {
        return DEVICE_PUBLIC_KEY.toJSONObject();
    }

    // -------------------------------- Key Attestation ----------------------------------------------------------------

    public static JWTClaimsSet.Builder getKeyAttestationClaimsBuilderWithDefaults(String nonce) {
        var now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(30)))
            .claim("key_storage", List.of("iso_18045_high"))
            .claim("user_authentication", List.of("iso_18045_high"))
            .claim("attested_keys", ATTESTED_KEYS.stream().map(JWK::toJSONObject).toList());
        if (nonce != null) {
            builder.claim("nonce", nonce);
        }
        return builder;
    }

    public static SignedJWT getValidKeyAttestationJwt(String nonce) {
        return getKeyAttestationJwt(getKeyAttestationClaimsBuilderWithDefaults(nonce).build(), KEY_ATTESTATION_TYPE);
    }

    public static SignedJWT getValidKeyAttestationJwtForDPoP(String nonce) {
        return getKeyAttestationJwtForDPoP(nonce, ATTESTED_KEYS_DPOP);
    }

    public static SignedJWT getKeyAttestationJwtForDPoP(String nonce, List<JWK> attestedKeys) {
        JWTClaimsSet.Builder builder = getKeyAttestationClaimsBuilderWithDefaults(nonce);
        return getKeyAttestationJwt(builder.claim("attested_keys", attestedKeys.stream().map(JWK::toJSONObject).toList()).build(), KEY_ATTESTATION_TYPE);
    }

    public static SignedJWT getValidKeyAttestationJwt(String nonce, int nrKeys) {
        List<JWK> keys = Collections.nCopies(nrKeys, ATTESTED_KEYS.getFirst());
        return getKeyAttestationJwt(
            getKeyAttestationClaimsBuilderWithDefaults(nonce)
                .claim("attested_keys", keys.stream().map(JWK::toJSONObject).toList())
                .build(), KEY_ATTESTATION_TYPE);
    }

    public static SignedJWT getKeyAttestationJwt(JWTClaimsSet claims, JOSEObjectType type) {
        return buildX5CJWT(claims, type, (ECPrivateKey) KEY_ATTESTATION_PRIVATE_KEY, KEY_ATTESTATION_CERTIFICATE_B64);
    }

    // -------------------------------- Seed Credential ----------------------------------------------------------------

    public static JWTClaimsSet.Builder getSeedCredentialClaimsBuilderWithDefaults() {
        var now = Instant.now();
        var identityData = new JsonMapper().convertValue(PidTestData.TEST_IDENTITY_DATA, Map.class);
        return new JWTClaimsSet.Builder(PidTestData.TEST_SEED_CREDENTIAL_CLAIMS)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(30)))
            .audience(ISSUER_IDENTIFIER_AUDIENCE)
            .subject(PidTestData.TEST_IDENTITY_DATA.restrictedId().id())
            .claim(PidTestData.IDENTITY_DATA_NAMESPACE, identityData)
            .jwtID(UUID.randomUUID().toString());
    }

    // -------------------------------- DPOP ---------------------------------------------------------------------------

    public static SignedJWT getDPoPProof(HttpMethod method, URI uri, Nonce nonce) {
        return getDPoPProof(DEVICE_KEY_PAIR, method, uri, null, nonce);
    }

    public static SignedJWT getDPoPProof(HttpMethod method, URI uri, DPoPAccessToken accessToken, Nonce nonce) {
        return getDPoPProof(DEVICE_KEY_PAIR, method, uri, accessToken, nonce);
    }

    public static SignedJWT getDPoPProof(JWK signingJwk, HttpMethod method, URI uri, DPoPAccessToken accessToken, Nonce nonce) {
        try {
            var proofFactory = new DefaultDPoPProofFactory(signingJwk, JWSAlgorithm.ES256);

            return proofFactory.createDPoPJWT(new JWTID(DPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH), method.name(), uri, new Date(), accessToken, nonce);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public static SignedJWT getDPoPProof(HttpMethod method, URI uri, Nonce nonce, SignedJWT keyAttestationJwt) {
        return getDPoPProof(DEVICE_KEY_PAIR, method, uri, nonce, keyAttestationJwt);
    }

    public static SignedJWT getDPoPProof(JWK signingJwk, HttpMethod method, URI uri, Nonce nonce, SignedJWT keyAttestation) {
        try {
            var proofFactory = new KeyAttestationDPopProofFactory(signingJwk, JWSAlgorithm.ES256);

            return proofFactory.createDPoPJWT(
                new JWTID(DPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH), method.name(), uri, new Date(),
                null, nonce, keyAttestation);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    private static PrivateKey readPrivateKey(String resourcePath, String algorithm) {
        try (var resource = TestUtils.class.getResourceAsStream(resourcePath)) {
            Objects.requireNonNull(resource, "JWT Private Key could not be found");

            byte[] tmp = resource.readAllBytes();
            return decodePrivateKey(new String(tmp, StandardCharsets.UTF_8), algorithm);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static List<X509Certificate> readClientCertificate(String resourcePath) {
        try {
            var is = TestUtils.class.getResourceAsStream(resourcePath);
            return CertificateFactory.getInstance("X.509").generateCertificates(is).stream().map(X509Certificate.class::cast).toList();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<com.nimbusds.jose.util.Base64> readClientCertificateB64(String resourcePath) {
        return readClientCertificate(resourcePath).stream().map(certificate -> {
            try {
                return com.nimbusds.jose.util.Base64.encode(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        }).toList();
    }

    private static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("[\r\n]", "");
        return pem.trim();
    }

    private static byte[] toEncodedBytes(final String pemEncoded) {
        final String normalizedPem = removeBeginEnd(pemEncoded);
        return Base64.getDecoder().decode(normalizedPem);
    }

    private static PrivateKey decodePrivateKey(final String pemEncoded, final String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(keySpec);
    }

    public static long randomSessionId() {
        return new Random().nextLong();
    }

    public static String generateAuthorizationCode() {
        return RandomUtil.randomString();
    }

    public static String generateRequestUri() {
        return "urn:ietf:params:oauth:request_uri:" + RandomUtil.randomString();
    }

    public static String generateIssuerState() {
        return RandomUtil.randomString();
    }

    public static String generateAccessToken() {
        return RandomUtil.randomString();
    }

    public static String generateRefreshTokenDigest() {
        return UUID.randomUUID().toString();
    }

    public static List<String> getDisclosures(String decodedSignature) {
        return Arrays.stream(decodedSignature.substring(decodedSignature.indexOf('~') + 1).split("~")).toList();
    }
}
