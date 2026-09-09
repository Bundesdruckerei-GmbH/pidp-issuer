/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;

import static de.bdr.pidp.issuer.base.FileResourceHelper.getFileInputStream;
import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;

class CredentialCreatorTestBase {
    protected final Instant nowV1 = Instant.now().truncatedTo(ChronoUnit.DAYS);
    protected final Instant now = OffsetDateTime.now(CredentialCreator.localZoneId).truncatedTo(ChronoUnit.DAYS).toInstant();
    protected final CredentialCreator.Validity validityV1 = new CredentialCreator.Validity(nowV1, nowV1.plusSeconds(ISSUANCE_CONFIG.getLifetime().toSeconds()));
    protected final CredentialCreator.Validity validity = new CredentialCreator.Validity(now, now.plusSeconds(ISSUANCE_CONFIG.getLifetime().toSeconds()));

    protected static Certificate[] givenSignerCertificateChain() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        var signerKeyStore = KeyStore.getInstance("PKCS12");
        signerKeyStore.load(getFileInputStream(ISSUANCE_CONFIG.getSignerPath()), ISSUANCE_CONFIG.getSignerPassword().toCharArray());

        return signerKeyStore.getCertificateChain(signerKeyStore.aliases().asIterator().next());
    }
}
