/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import de.bdr.pidp.issuer.base.jwk.LazyJWKSource;
import de.bdr.pidp.issuer.base.jwt.JWEDecryptionKeySelector;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidCredentialRequestException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidEncryptionParametersException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.RequestEncryptionService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;

import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class IssuanceRequestFactory {

    private final JWTProcessor<?> encryptedCredentialRequestProcessor;
    private final boolean requestEncryptionSupported;
    private final boolean requestEncryptionRequired;
    private final boolean responseEncryptionSupported;
    private final boolean responseEncryptionRequired;

    public IssuanceRequestFactory(RequestEncryptionService requestEncryptionService, CredentialIssuerMetadata metadata) {
        var requestEncryption = metadata.credentialRequestEncryption();
        requestEncryptionSupported = requestEncryption != null;
        requestEncryptionRequired = requestEncryptionSupported && requestEncryption.encryptionRequired();
        List<EncryptionMethod> encryptionMethods = requestEncryptionSupported ? requestEncryption.encValuesSupported() : Collections.emptyList();

        var responseEncryption = metadata.credentialResponseEncryption();
        responseEncryptionSupported = responseEncryption != null;
        responseEncryptionRequired = responseEncryptionSupported && responseEncryption.encryptionRequired();

        var processor = new DefaultJWTProcessor<>();
        processor.setJWETypeVerifier(new DefaultJOSEObjectTypeVerifier<>());
        // KeyID gets string compared with aliases in JWKSet, so no sanitizing/validation is necessary here
        processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(encryptionMethods,
            new LazyJWKSource<>(_ -> requestEncryptionService.getPrivateKeySet())));
        processor.setJWEDecrypterFactory(new DefaultJWEDecrypterFactory());
        this.encryptedCredentialRequestProcessor = processor;
    }

    public CredentialRequest getCredentialRequest(HttpMethod method, boolean fromEncryptedRequest, MultiValueMap<String, String> allHeaders, @Nullable String body) throws InvalidCredentialRequestException {
        if (body == null || body.isEmpty()) {
            throw new InvalidCredentialRequestException("Request body is missing");
        }
        if (!requestEncryptionSupported && fromEncryptedRequest) {
            throw new InvalidCredentialRequestException("Credential request encryption not supported");
        }
        if (requestEncryptionRequired && !fromEncryptedRequest) {
            throw new InvalidCredentialRequestException("Credential request encryption required");
        }
        final String requestBody;
        if (fromEncryptedRequest) {
            requestBody = decryptCredentialRequest(body);
        } else {
            requestBody = body;
        }
        var credentialRequest = new CredentialRequest(method.name(), readHeaders(allHeaders), requestBody);
        if (!responseEncryptionSupported && credentialRequest.getCredentialEncryption() != null) {
            throw new InvalidCredentialRequestException("Credential response encryption not supported");
        }
        if (responseEncryptionRequired && credentialRequest.getCredentialEncryption() == null) {
            throw new InvalidCredentialRequestException("Credential response encryption required");
        }
        if (credentialRequest.getCredentialEncryption() != null && !fromEncryptedRequest) {
            throw new InvalidCredentialRequestException("Credential response encryption requires request to also be encrypted");
        }
        return credentialRequest;
    }

    private String decryptCredentialRequest(String credentialRequest) {
        try {
            var jwe = EncryptedJWT.parse(credentialRequest);
            var claims = encryptedCredentialRequestProcessor.process(jwe, null);
            return claims.toString();
        } catch (KeySourceException e) {
            throw new InvalidEncryptionParametersException("Encrypted credential request invalid: " + e.getMessage(), e);
        } catch (BadJOSEException e) {
            throw new InvalidCredentialRequestException("Encrypted credential request invalid: " + e.getMessage(), e);
        } catch (ParseException | JOSEException e) {
            throw new InvalidCredentialRequestException("Encrypted credential request invalid", e);
        }
    }

    private static Map<String, List<String>> readHeaders(MultiValueMap<String, String> allHeaders) {
        Map<String, List<String>> headers = new HashMap<>();
        allHeaders.forEach((k, v) -> headers.put(k.toLowerCase(), v));
        return headers;
    }
}
