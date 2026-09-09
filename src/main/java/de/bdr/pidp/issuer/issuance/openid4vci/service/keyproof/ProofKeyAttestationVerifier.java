/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.base.KeyAttestationSecurityContext;
import de.bdr.pidp.issuer.base.KeyAttestationVerifier;
import de.bdr.pidp.issuer.base.jwt.InvalidNonceJWTException;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.AttackPotentialResistance;
import de.bdr.pidp.issuer.issuance.config.model.ProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidNonceException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

@NullMarked
public class ProofKeyAttestationVerifier extends KeyAttestationVerifier {

    private final CNonceService cNonceService;

    public ProofKeyAttestationVerifier(CNonceService cNonceService, Set<JWSAlgorithm> signingAlgValuesSupported, List<String> supportedKeyStorage, List<String> supportedUserAuthentication, boolean allowSelfSigned, Duration proofTimeTolerance) {
        super(signingAlgValuesSupported, supportedKeyStorage, supportedUserAuthentication, allowSelfSigned, proofTimeTolerance);
        this.cNonceService = cNonceService;
    }

    @SuppressWarnings("java:S2637") // CNonceService is initialized via this(...)
    public ProofKeyAttestationVerifier(CNonceService cNonceService, IssuanceConfiguration config, ProofType proofType) {
        var algsSupported = new HashSet<>(proofType.proofSigningAlgValuesSupported());
        var keyStorage = extractKeyStorage(proofType);
        var userAuthentication = extractUserAuthentication(proofType);

        this(cNonceService,
            algsSupported,
            keyStorage,
            userAuthentication,
            config.allowSelfSignedAttestationCert(),
            config.getProofTimeTolerance());
    }

    @Override
    public List<JWK> verify(SignedJWT jwt, Set<X509Certificate> cert, Collection<String> validatedNonces) {
        var ctx = new KeyAttestationSecurityContext(cert, cNonceCheck(validatedNonces));
        try {
            jwtProcessor.process(jwt, ctx);
        } catch (InvalidNonceJWTException e) {
            throw new InvalidNonceException("Unexpected JWT nonce (nonce) claim", "Nonce invalid: " + e.getMessage(), e);
        } catch (BadJOSEException | KeySourceException e) {
            throw new InvalidProofException("Proof invalid: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new InvalidProofException(null, "Proof invalid", e);
        }

        return ctx.getKeys();
    }

    private Predicate<@Nullable Nonce> cNonceCheck(Collection<String> validatedNonces) {
        return nonce -> {
            if (nonce == null) {
                return false;
            }
            if (validatedNonces.contains(nonce.getValue())) {
                return true;
            }
            if (cNonceService.consume(nonce.getValue())) {
                validatedNonces.add(nonce.getValue());
                return true;
            }
            return false;
        };
    }

    private static List<String> extractKeyStorage(ProofType proofType) {
        var required = proofType.keyAttestationsRequired();
        if (required == null) {
            return Collections.emptyList();
        }
        var keyStorage = required.keyStorage();
        if (keyStorage == null) {
            return Collections.emptyList();
        }
        return keyStorage.stream().map(AttackPotentialResistance::getName).toList();
    }

    private static List<String> extractUserAuthentication(ProofType proofType) {
        var required = proofType.keyAttestationsRequired();
        if (required == null) {
            return Collections.emptyList();
        }
        var userAuthentication = required.userAuthentication();
        if (userAuthentication == null) {
            return Collections.emptyList();
        }
        return userAuthentication.stream().map(AttackPotentialResistance::getName).toList();
    }
}
