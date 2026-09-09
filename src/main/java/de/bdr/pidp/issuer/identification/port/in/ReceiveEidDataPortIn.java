/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.in;

import java.net.URL;

public interface ReceiveEidDataPortIn {

    URL processSamlResponse(String saMLResponse, String relayState, String sigAlg, String signature);
}
