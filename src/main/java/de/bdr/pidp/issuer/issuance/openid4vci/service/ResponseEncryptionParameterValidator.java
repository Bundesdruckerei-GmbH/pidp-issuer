/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidEncryptionParametersException;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@NullMarked
@Service
public class ResponseEncryptionParameterValidator {

    private final List<EncryptionMethod> encryptionMethods;
    private final List<JWEAlgorithm> jweAlgorithms;

    public ResponseEncryptionParameterValidator(CredentialIssuerMetadata metadata) {
        var resEnc = metadata.credentialResponseEncryption();
        if (resEnc == null) {
            encryptionMethods = Collections.emptyList();
            jweAlgorithms = Collections.emptyList();
        } else {
            encryptionMethods = resEnc.encValuesSupported();
            jweAlgorithms = resEnc.algValuesSupported();
        }
    }

    public JWEAlgorithm validate(JWK cresEncKaPubk, EncryptionMethod encMethod) {
        var jwkAlg = cresEncKaPubk.getAlgorithm();
        if (jwkAlg == null) {
            throw new InvalidEncryptionParametersException("Missing response encryption JWE algorithm in provided JWK");
        }
        var encAlg = jweAlgorithms.stream().filter(jwkAlg::equals).findFirst()
            .orElseThrow(() -> new InvalidEncryptionParametersException("Unsupported response encryption JWE algorithm in provided response encryption JWK"));

        if (!encryptionMethods.contains(encMethod)) {
            throw new InvalidEncryptionParametersException("Unsupported response encryption method");
        }
        return encAlg;
    }
}
