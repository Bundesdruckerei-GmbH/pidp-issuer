/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import de.bdr.pidp.issuer.authorization.core.domain.AuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.AuthorizeResult;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthorizationResult;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthorizeAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.FinishAuthorizationAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.FinishAuthException;
import de.bdr.pidp.issuer.authorization.core.exception.OAuthException;
import de.bdr.pidp.issuer.authorization.core.exception.RequestUriExpiredException;
import de.bdr.pidp.issuer.authorization.core.particle.AuthorizationHandler;
import de.bdr.pidp.issuer.authorization.core.particle.ClientIdValidator;
import de.bdr.pidp.issuer.authorization.core.particle.FinishAuthorizationHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RequestOrderValidator;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.authorization.port.out.AuthorizeDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.FinishAuthorizationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.PidServerException;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.time.Instant;
import java.util.Set;

import static de.bdr.pidp.issuer.authorization.config.MdcKeys.MDC_CLIENT_ID;

@RequiredArgsConstructor
@Service
public class AuthorizationService {

    private final ClientIdValidator clientIdValidator;
    private final AuthorizeDataPortOut authorizeDataPortOut;
    private final FinishAuthorizationDataPortOut finishAuthorizationDataPortOut;
    private final AuthorizationHandler authorizationHandler;
    private final DPoPNonceService dPoPNonceService;
    private final FinishAuthorizationHandler finishAuthorizationHandler;
    private final Set<JWSAlgorithm> signingAlgValuesSupported;

    public AuthorizeResult processAuthRequest(AuthRequest request) {
        var requestClientId = request.getClientId();
        MDC.put(MDC_CLIENT_ID, requestClientId);

        AuthorizeAuthSession authorizeAuthSession = authorizeDataPortOut.loadByRequestUri(request.getRequestUri());
        if (authorizeAuthSession.getRequestUriExpirationTime().isBefore(Instant.now())) {
            DPoPTokenError dpopTokenError = DPoPTokenError.INVALID_TOKEN
                .setDescription("Request uri expired")
                .setJWSAlgorithms(signingAlgValuesSupported)
                .setRealm("oid4vci");
            throw new RequestUriExpiredException(dpopTokenError);
        }

        String savedClientId = authorizeAuthSession.getClientId();

        clientIdValidator.validateClientId(requestClientId, savedClientId);

        AuthorizeResult authorizeResult;
        try {
            RequestOrderValidator.validateRequest(authorizeAuthSession, Requests.AUTHORIZATION_REQUEST);
            URL samlAuthRequestUrl = authorizationHandler.processAuthRequest(authorizeAuthSession);

            authorizeResult = new AuthorizeResult(samlAuthRequestUrl);
            authorizeAuthSession.setNextExpectedRequest(Requests.FINISH_AUTHORIZATION_REQUEST);
        } finally {
            authorizeDataPortOut.save(authorizeAuthSession);
        }
        return authorizeResult;
    }

    public FinishAuthorizationResult processFinishAuthRequest(FinishAuthRequest request) {
        var issuerState = request.getIssuerState();
        FinishAuthorizationAuthSession finishAuthorizationAuthSession = finishAuthorizationDataPortOut.loadByIssuerState(issuerState);

        FinishAuthorizationResult finishAuthorizationResult;
        try {
            RequestOrderValidator.validateRequest(finishAuthorizationAuthSession, Requests.FINISH_AUTHORIZATION_REQUEST);
            Nonce nonce = dPoPNonceService.provideAndSave(finishAuthorizationAuthSession);
            String redirectUri = finishAuthorizationHandler.processFinishAuthRequest(request, finishAuthorizationAuthSession);

            finishAuthorizationResult = new FinishAuthorizationResult(redirectUri, nonce);
            finishAuthorizationAuthSession.setNextExpectedRequest(Requests.TOKEN_REQUEST);
        } catch (OAuthException | IdentificationFailedException | PidServerException e) {
            throw new FinishAuthException(finishAuthorizationAuthSession.getRedirectUri(), finishAuthorizationAuthSession.getState(), e);
        } finally {
            finishAuthorizationDataPortOut.save(finishAuthorizationAuthSession);
        }
        return finishAuthorizationResult;
    }
}
