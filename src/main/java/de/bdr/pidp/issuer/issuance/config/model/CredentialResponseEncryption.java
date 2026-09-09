/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import de.bdr.pidp.issuer.base.JSONRepresentation;
import org.jspecify.annotations.NullMarked;

import java.util.List;

@NullMarked
public interface CredentialResponseEncryption extends JSONRepresentation {
    List<JWEAlgorithm> algValuesSupported();
    List<EncryptionMethod> encValuesSupported();
    boolean encryptionRequired();
}
