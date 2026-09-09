/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.out.persistence;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.net.URI;
import java.time.Instant;

@Setter
@Getter
@Entity
@Table(name = "auth_session")
public class AuthSessionEntity {
    @Id
    @GeneratedValue
    private long sessionId;
    @Column(name = "access_token_id")
    private String accessTokenID;
    private String authorizationCode;
    private Instant authorizationCodeExpirationTime;
    @Column(name = "client_attestation_status_list_ref_uri")
    private URI clientAttestationStatusListRefURI;
    @Column(name = "client_attestation_status_list_ref_index")
    private Integer clientAttestationStatusListRefIndex;
    private String clientId;
    private String codeChallenge;
    private String codeChallengeMethod;
    private String dpopNonce;
    private Instant dpopNonceExpirationTime;
    private String seedCredentialData;
    private String seedCredentialRef;
    private String seedCredentialSub;
    private Instant seedCredentialExpirationTime;
    private String issuerState;
    private String redirectUri;
    @Column(name = "refresh_token_id")
    private String refreshTokenID;
    private String requestUri;
    private Instant requestUriExpirationTime;
    private String scope;
    private String state;
    @Column
    @Enumerated(EnumType.STRING)
    private Requests nextExpectedRequest;
    private Instant expires;
    @Column(insertable = false, updatable = false)
    private Instant created;
}
