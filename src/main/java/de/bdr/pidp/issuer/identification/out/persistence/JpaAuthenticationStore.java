/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.out.persistence;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.identification.core.AuthenticationStore;
import de.bdr.pidp.issuer.identification.core.exception.AuthenticationNotFoundException;
import de.bdr.pidp.issuer.identification.core.model.Authentication;
import de.bdr.pidp.issuer.identification.core.model.AuthenticationState;
import jakarta.transaction.Transactional;
import jakarta.validation.constraints.NotNull;
import lombok.val;
import org.jmolecules.architecture.hexagonal.SecondaryAdapter;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Instant;
import java.util.Collection;

@SecondaryAdapter
@Component
public class JpaAuthenticationStore implements AuthenticationStore {
    private final AuthenticationRepository repo;

    public JpaAuthenticationStore(AuthenticationRepository repo) {
        this.repo = repo;

    }

    @Override
    public long countAuthenticatedSessions() {
        return repo.countByAuthenticationStateAndValidUntilAfter(AuthenticationState.AUTHENTICATED, Instant.now());
    }

    @Transactional
    @Override
    public Authentication findByTokenId(String tokenId) {
        var entity = repo.findByTokenId(tokenId);
        if (entity == null) {
            throw new AuthenticationNotFoundException("No authentication found for token id: " + tokenId);
        }
        return toDomainAuthentication(entity);
    }


    @Transactional
    @Override
    public Authentication findBySamlId(String samlId) {
        var entity = repo.findBySamlId(samlId);
        if (entity == null) {
            throw new AuthenticationNotFoundException("No authentication found for saml id: " + samlId);
        }
        return toDomainAuthentication(entity);
    }

    @Transactional
    @Override
    public Authentication findByReferenceId(String referenceId) {
        var entity = repo.findByReferenceId(referenceId);
        if (entity == null) {
            throw new AuthenticationNotFoundException("No authentication found for reference id: " + referenceId);
        }
        return toDomainAuthentication(entity);
    }

    @Transactional
    @Override
    public Authentication findBySessionId(String sessionId) {
        var entity = repo.findBySessionId(sessionId);
        if (entity == null) {
            throw new AuthenticationNotFoundException("No authentication found for session id: " + sessionId);
        }
        return toDomainAuthentication(entity);
    }

    @Transactional
    @Override
    public int deleteByAuthenticationStateIn(Collection<AuthenticationState> authenticationStates) {
        return repo.deleteByAuthenticationStateIn(authenticationStates);
    }

    @Transactional
    @Override
    public int updateStateByValidUntilBeforeAndAuthenticationStateNotIn(AuthenticationState newState, Instant validUntil, Collection<AuthenticationState> authenticationStates) {
        return repo.updateStateByValidUntilBeforeAndAuthenticationStateNotIn(newState, validUntil, authenticationStates);
    }

    @Transactional
    @Override
    public void createWithSessionAndToken(Authentication authentication) {
        var entity = new AuthenticationEntity(authentication);

        repo.save(entity);
    }


    @Transactional
    @Override
    public void updateWithSamlIdentifiedByTokenAndFormerState(Authentication authentication, AuthenticationState formerState) {
        var newState = authentication.getAuthenticationState();
        var samlId = authentication.getSamlId();
        var tokenId = authentication.getTokenId();
        if (repo.updateSamlIdByTokenIdAndAuthenticationState(newState, samlId, tokenId, formerState) != 1) {
            throw new AuthenticationNotFoundException("Could not update saml id %s for token id %s and state %s".formatted(samlId, tokenId, formerState));
        }
    }

    @Transactional
    @Override
    public void updateWithReferenceIdIdentifiedBySamlAndFormerState(Authentication authentication, AuthenticationState formerState) {
        var newState = authentication.getAuthenticationState();

        var referenceId = authentication.getReferenceId();
        var samlId = authentication.getSamlId();
        if (repo.updateReferenceIdBySamlIdAndAuthenticationState(newState, referenceId, samlId, formerState) != 1) {
            throw new AuthenticationNotFoundException("Could not update reference id %s for saml id %s and state %s".formatted(referenceId, samlId, formerState));
        }
    }

    @Transactional
    @Override
    public void updateWithChangedSessionValidUntilIdentifiedByReferenceAndFormerState(Authentication authentication, String oldSessionId, AuthenticationState formerState) {
        if (repo.updateChangedSessionValidUntilByReferenceAndFormerState(authentication.getAuthenticationState(), authentication.getSessionId(), authentication.getValidUntil(), oldSessionId, formerState, authentication.getReferenceId()) != 1) {
            throw new AuthenticationNotFoundException("Authentication to be deleted not found with session id %s, reference id %s and authentication state %s".formatted(oldSessionId, authentication.getReferenceId(), formerState.name()));
        }
    }

    @Transactional
    @Override
    public void removeIdentifiedBySessionAndFormerState(Authentication authentication, String sessionId, AuthenticationState formerState) {
        if (repo.deleteBySessionIdAndAuthenticationState(sessionId, formerState) != 1) {
            throw new AuthenticationNotFoundException("Authentication removal for session %s and authentication state %s not successful".formatted(sessionId, formerState));
        }
    }

    private Authentication toDomainAuthentication(@NotNull AuthenticationEntity entity) {
        var state = entity.getAuthenticationState();
        try {
            val redirectUrl = URI.create(entity.getRedirectUrl()).toURL();
            return switch (state) {
                case INITIALIZED -> Authentication.restoreInitialized(
                        entity.getSessionId(),
                        entity.getTokenId(),
                        entity.getValidUntil(),
                        entity.getCreated(),
                        entity.getExternalId(),
                        redirectUrl
                );
                case STARTED -> Authentication.restoreStarted(
                        entity.getSessionId(),
                        entity.getTokenId(),
                        entity.getSamlId(),
                        entity.getValidUntil(),
                        entity.getCreated(),
                        entity.getExternalId(),
                        redirectUrl);
                case RESPONDED -> Authentication.restoreResponded(
                        entity.getSessionId(),
                        entity.getTokenId(),
                        entity.getSamlId(),
                        entity.getReferenceId(),
                        entity.getValidUntil(),
                        entity.getCreated(),
                        entity.getExternalId(),
                        redirectUrl
                );
                case AUTHENTICATED -> Authentication.restoreAuthenticated(
                        entity.getSessionId(),
                        entity.getTokenId(),
                        entity.getSamlId(),
                        entity.getReferenceId(),
                        entity.getValidUntil(),
                        entity.getCreated(),
                        entity.getExternalId(),
                        redirectUrl
                );
                case TIMEOUT -> Authentication.restoreTimeout(
                        entity.getSessionId(),
                        entity.getTokenId(),
                        entity.getSamlId(),
                        entity.getReferenceId(),
                        entity.getValidUntil(),
                        entity.getCreated(),
                        entity.getExternalId(),
                        redirectUrl
                );
                case TERMINATED -> Authentication.restoreTerminated(
                        entity.getSessionId(),
                        entity.getTokenId(),
                        entity.getSamlId(),
                        entity.getReferenceId(),
                        entity.getValidUntil(),
                        entity.getCreated(),
                        entity.getExternalId(),
                        redirectUrl
                );
            };
        } catch (MalformedURLException e) {
            throw new PidServerException("malformed url", e);
        }
    }
}
