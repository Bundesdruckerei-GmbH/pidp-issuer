/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

import CryptoServerAPI.CryptoServerException;
import CryptoServerCXI.CryptoServerCXI;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMConfiguration.HSMGroupConfiguration;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
class HSMAuthenticationService {

    private final HSMGroupConfiguration hsmConfiguration;
    private CryptoServerCXI cxi;

    public HSMAuthenticationService(HSMGroupConfiguration hsmConfiguration) {
        this.hsmConfiguration = hsmConfiguration;
        try {
            this.cxi = getHSMConnection();
        } catch (IOException | CryptoServerException e) {
            throw new PidServerException("Could not init HSM connection", e);
        }
    }

    protected synchronized void ensureAuthenticated() throws CryptoServerException, IOException {
        boolean notAuthenticated;
        try {
            notAuthenticated = (cxi.getAuthState() == 0);
        } catch (CryptoServerException e) {
            log.warn("Could not get AuthState: {}", e.getMessage());
            notAuthenticated = true;
            cxi = getHSMConnection();
        }

        if (notAuthenticated) {
            HSMConfiguration.CryptoUser cryptoUser = hsmConfiguration.cryptoUser();
            cxi.logon(cryptoUser.getName(), null, cryptoUser.getPassword().getBytes(StandardCharsets.UTF_8));
            cxi.setKeepSessionAlive(true);
        }
    }

    protected CryptoServerCXI getCxi() {
        return cxi;
    }

    protected String getGroup() {
        return hsmConfiguration.cryptoUser().getGroup();
    }

    private CryptoServerCXI getHSMConnection() throws CryptoServerException, IOException {
        try {
            CryptoServerCXI cryptoServerCXI = new CryptoServerCXI(hsmConfiguration.cxiDevice(),
                (int) hsmConfiguration.cxiConnectionTimeout().toMillis());
            cryptoServerCXI.setTimeout((int) hsmConfiguration.cxiCommandTimeout().toMillis());
            return cryptoServerCXI;
        } finally {
            log.info("CryptoServerCXI initialized for group {}", getGroup());
        }
    }
}
