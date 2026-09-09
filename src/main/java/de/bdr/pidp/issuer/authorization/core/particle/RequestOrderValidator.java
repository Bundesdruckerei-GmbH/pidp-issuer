/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionView;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RequestOrderValidator {

    public static void validateRequest(AuthSessionView authSession, Requests request){
        if (authSession.getNextExpectedRequest() != request) {
            throw InvalidRequestException.forWrongRequestOrder(request.getPath(), request.name());
        }
    }
}
