/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.domain.ParRequest;
import de.bdr.pidp.issuer.authorization.core.domain.ParResult;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.ParAuthSession;
import de.bdr.pidp.issuer.authorization.core.particle.ClientAttestationValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ClientIdValidator;
import de.bdr.pidp.issuer.authorization.core.particle.PKCEValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ParHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RedirectUriValidator;
import de.bdr.pidp.issuer.authorization.core.particle.RequestOrderValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ScopeValidator;
import de.bdr.pidp.issuer.authorization.core.particle.StateValidator;
import de.bdr.pidp.issuer.authorization.port.out.ParDataPortOut;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import static de.bdr.pidp.issuer.authorization.config.MdcKeys.MDC_CLIENT_ID;

@RequiredArgsConstructor
@Service
public class ParService {

    private final PKCEValidator pkceValidator;
    private final ClientIdValidator clientIdValidator;
    private final RedirectUriValidator redirectUriValidator;
    private final ScopeValidator scopeValidator;
    private final StateValidator stateValidator;
    private final ClientAttestationValidator clientAttestationValidator;
    private final ParHandler parHandler;
    private final ParDataPortOut parDataPortOut;

    public ParResult processPushedAuthRequest(ParRequest parRequest) {
        MDC.put(MDC_CLIENT_ID, parRequest.getClientId());

        clientIdValidator.validateClientId(parRequest.getClientId());
        pkceValidator.validateCodeChallenge(parRequest.getCodeChallenge(), parRequest.getCodeChallengeMethod());
        redirectUriValidator.validateRedirectUri(parRequest.getRedirectUri());
        scopeValidator.validateScope(parRequest.getScope());
        String state = parRequest.getState();
        if (state != null) {
            stateValidator.validateState(state);
        }
        var attestationValues = clientAttestationValidator.validateClientAttestation(
            parRequest.getAttestation(), parRequest.getAttestationPoP(), parRequest.getClientId());

        ParAuthSession parAuthSession = parDataPortOut.init();

        parAuthSession.addValidatedRequestParams(
            parRequest.getCodeChallenge(),
            parRequest.getCodeChallengeMethod().getValue(),
            parRequest.getClientId(),
            parRequest.getRedirectUri(),
            parRequest.getScope(),
            attestationValues.statusListRef(),
            parRequest.getState());

        ParResult parResult;
        try {
            RequestOrderValidator.validateRequest(parAuthSession, Requests.PUSHED_AUTHORIZATION_REQUEST);
            parResult = parHandler.processPushedAuthRequest(parRequest, parAuthSession);
            parAuthSession.setNextExpectedRequest(Requests.AUTHORIZATION_REQUEST);
        } finally {
            parDataPortOut.save(parAuthSession);
        }
        return parResult;

    }
}
