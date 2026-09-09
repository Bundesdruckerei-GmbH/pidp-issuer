/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.in;

import de.bdr.pidp.issuer.identification.in.api.EidApi;
import de.bdr.pidp.issuer.identification.port.in.ReceiveEidDataPortIn;
import io.micrometer.core.annotation.Timed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class EidController implements EidApi {

    private final ReceiveEidDataPortIn receiveEidDataPortIn;

    public EidController(ReceiveEidDataPortIn receiveEidDataPortIn) {
        this.receiveEidDataPortIn = receiveEidDataPortIn;
    }

    @Timed
    @Override
    public ResponseEntity<Void> getSamlConsumer(String saMLResponse, String relayState, String sigAlg, String signature) {
        var redirectUrl = receiveEidDataPortIn.processSamlResponse(saMLResponse, relayState, sigAlg, signature);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.LOCATION, redirectUrl.toString());
        return new ResponseEntity<>(headers, HttpStatus.SEE_OTHER);
    }
}
