/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import de.bdr.pidp.issuer.base.jwt.InvalidNonceJWTException;
import de.bdr.pidp.issuer.base.jwt.JWTClaimsVerifier;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@NullMarked
public class KeyAttestationClaimsVerifier extends JWTClaimsVerifier<KeyAttestationSecurityContext> {

    @Nullable
    private final List<String> supportedKeyStorage;

    @Nullable
    private final List<String> supportedUserAuthentication;

    public KeyAttestationClaimsVerifier(@Nullable final List<String> supportedKeyStorage,
                                        @Nullable final List<String> supportedUserAuthentication,
                                        final int maxClockSkew) {
        this.supportedKeyStorage = supportedKeyStorage;
        this.supportedUserAuthentication = supportedUserAuthentication;
        setMaxClockSkew(maxClockSkew);
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, KeyAttestationSecurityContext context) throws BadJWTException {

        verifyTimeClaims(claimsSet);

        verifyNonceClaim(claimsSet, context);

        verifySupportedKeyStorageClaim(claimsSet);

        verifySupportedUserAuthenticationClaim(claimsSet);

        final List<JWK> attestedKeys = verifyAttestedKeysClaim(claimsSet);

        context.addKeys(attestedKeys);
    }

    private void verifyTimeClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        final Date nowRef = new Date();

        verifyIssuedAtClaim(claimsSet, nowRef);

        verifyExpirationClaimIfPresent(claimsSet, nowRef);
    }

    private void verifyNonceClaim(JWTClaimsSet claimsSet, KeyAttestationSecurityContext context) throws BadJWTException {
        var nonceCheck = context.getNonceCheck();
        if (nonceCheck != null) {
            final String tokenNonce;

            try {
                tokenNonce = claimsSet.getStringClaim("nonce");
            } catch (ParseException e) {
                throw new BadJWTException("Invalid JWT nonce (nonce) claim: " + e.getMessage());
            }

            if (tokenNonce == null) {
                throw BadJWTExceptions.MISSING_NONCE_CLAIM_EXCEPTION;
            }

            if (!nonceCheck.test(Nonce.parse(tokenNonce))) {
                throw new InvalidNonceJWTException("Unexpected JWT nonce (nonce) claim: '%s'".formatted(tokenNonce));
            }
        }
    }

    private void verifySupportedKeyStorageClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        if (supportedKeyStorage != null && !supportedKeyStorage.isEmpty()) {
            final List<String> keyStorage;

            try {
                keyStorage = claimsSet.getStringListClaim("key_storage");
            } catch (ParseException e) {
                throw new BadJWTException("Invalid JWT key_storage claim: " + e.getMessage());
            }

            if (keyStorage == null || keyStorage.isEmpty()) {
                throw new BadJWTException("Missing JWT key_storage claim");
            }

            if (Collections.disjoint(supportedKeyStorage, keyStorage)) {
                throw new BadJWTException("Invalid JWT key_storage claim: does not contain supported key_storage");
            }
        }
    }

    private void verifySupportedUserAuthenticationClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        if (supportedUserAuthentication != null && !supportedUserAuthentication.isEmpty()) {
            final List<String> userAuthentication;

            try {
                userAuthentication = claimsSet.getStringListClaim("user_authentication");
            } catch (ParseException e) {
                throw new BadJWTException("Invalid JWT user_authentication claim: " + e.getMessage());
            }

            if (userAuthentication == null || userAuthentication.isEmpty()) {
                throw new BadJWTException("Missing JWT user_authentication claim");
            }

            if (Collections.disjoint(supportedUserAuthentication, userAuthentication)) {
                throw new BadJWTException("Invalid JWT user_authentication claim: does not contain supported user_authentication");
            }
        }
    }

    private List<JWK> verifyAttestedKeysClaim(JWTClaimsSet claimsSet) throws BadJWTException {
        final List<Object> attestedKeysList;

        try {
            attestedKeysList = claimsSet.getListClaim("attested_keys");
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT attested_keys claim: " + e.getMessage());
        }

        if (attestedKeysList == null || attestedKeysList.isEmpty()) {
            throw new BadJWTException("Missing JWT attested_keys claim");
        }

        final List<JWK> attestedKeys = new ArrayList<>();

        for (Object attestedKeyObject : attestedKeysList) {
            if (attestedKeyObject instanceof Map<?, ?> attestedKeyMap) {
                Map<String, Object> attestedKey = attestedKeyMap.entrySet().stream()
                    .collect(Collectors.toMap(e -> e.getKey().toString(), Map.Entry::getValue));
                try {
                    attestedKeys.add(JWK.parse(attestedKey));
                } catch (ParseException e) {
                    throw new BadJWTException("Invalid JWT attested_keys claim: " + e.getMessage());
                }
            } else {
                throw new BadJWTException("Invalid JWT attested_keys claim: is not a map");
            }
        }

        return attestedKeys;
    }
}
