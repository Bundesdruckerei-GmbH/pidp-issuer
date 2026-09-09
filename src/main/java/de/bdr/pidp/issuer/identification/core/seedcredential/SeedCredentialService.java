/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@NullMarked
@Service
public class SeedCredentialService {

    private final SeedCredentialKeyOperator seedCredentialKeyOperator;
    private final EidDataMapper mapper;

    public SeedCredentialService(IdentificationConfiguration identificationConfiguration, SeedCredentialKeyOperator seedCredentialKeyOperator) {
        this.seedCredentialKeyOperator = seedCredentialKeyOperator;
        this.mapper = new EidDataMapper(identificationConfiguration.getCredentialIssuerIdentifier());
    }

    public SeedCredentialData createSeedCredential(IdentityData identityData) {
        var claims = mapper.map(identityData);

        SignedJWT signedSeedCredential = seedCredentialKeyOperator.signSeedCredential(claims);
        JWEObject encryptedSeedCredential = seedCredentialKeyOperator.encrypt(signedSeedCredential);

        // Serialize to JWE compact form
        return new SeedCredentialData(encryptedSeedCredential.serialize(), identityData, claims.getJWTID(), claims.getSubject(), claims.getExpirationTime().toInstant());
    }

    /**
     * @throws SeedException when Seed Credential could not be processed properly
     */
    public SeedCredentialData verifySeedCredentialAndGetData(String seedCredential) {
        EncryptedJWT jwe;
        try {
            jwe = EncryptedJWT.parse(seedCredential);
        } catch (ParseException e) {
            throw new SeedException("Seed Credential could not be parsed", e);
        }

        var claims = seedCredentialKeyOperator.decryptAndVerify(jwe);

        try {
            IdentityData identityData = mapper.map(claims);
            return new SeedCredentialData(seedCredential, identityData, claims.getJWTID(), claims.getSubject(), claims.getExpirationTime().toInstant());
        } catch (ParseException e) {
            throw new SeedException("Seed Credential is invalid", e);
        }
    }
}
