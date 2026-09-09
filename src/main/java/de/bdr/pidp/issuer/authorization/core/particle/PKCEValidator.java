/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;
import java.util.Objects;

@Component
public class PKCEValidator {
    private final List<CodeChallengeMethod> codeChallengeMethods;

    public PKCEValidator(ReadOnlyAuthMetadata metadata) {
        codeChallengeMethods = metadata.getCodeChallengeMethods();
    }

    public void validateCodeChallenge(String codeChallenge, CodeChallengeMethod codeChallengeMethod) {
        if (!codeChallengeMethods.contains(codeChallengeMethod)) {
            throw new InvalidRequestException("Unsupported code challenge method");
        }
        if (codeChallengeMethod.getValue().equals(CodeChallengeMethod.S256.getValue())) {
            validateS256CodeChallenge(codeChallenge);
        } else {
            throw new UnsupportedOperationException("No implementation for code challenge method " + codeChallengeMethod.getValue());
        }
    }

    public void validateCodeVerifier(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        var method = CodeChallengeMethod.parse(codeChallengeMethod);

        final CodeChallenge computedCodeChallenge;
        try {
            final CodeVerifier verifier = new CodeVerifier(codeVerifier);
            computedCodeChallenge = CodeChallenge.compute(method, verifier);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new InvalidRequestException("Invalid code verifier", e);
        }
        if (!Objects.equals(computedCodeChallenge.getValue(), codeChallenge)) {
            throw new InvalidGrantException("Invalid code verifier");
        }
    }

    private static void validateS256CodeChallenge(String codeChallenge) {
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(codeChallenge);
            if (bytes.length != 32) {
                throw new InvalidRequestException("Invalid code challenge", "Invalid code challenge length");
            }
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid code challenge", "Invalid code challenge base64", e);
        }
    }
}
