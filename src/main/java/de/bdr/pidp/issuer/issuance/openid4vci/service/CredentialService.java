/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.identitydata.DocumentType;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.issuance.core.CredentialCreationService;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidIdentityDataException;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationAdapter;
import de.bdr.pidp.issuer.issuance.openid4vci.out.identification.IdentificationAdapter;
import de.bdr.pidp.issuer.issuance.openid4vci.out.identification.InvalidSeedCredentialException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialResponseEncryptionResult;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialResult;
import de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.CredentialRequestDPoPValidator;
import de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.MissingDPoPNonceException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.AttestationKeyProofHandler;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.JwtKeyProofHandler;
import de.bdr.pidp.issuer.issuance.policy.InvalidIssuanceDecision;
import de.bdr.pidp.issuer.issuance.policy.IssuanceDecision;
import de.bdr.pidp.issuer.issuance.policy.PidIdentityDataValidator;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.IssuanceDPoPValidationException.useDPoPNonce;

@Service
@Slf4j
public class CredentialService {
    private static final String GERMAN_ID_DEFAULT_NATIONALITY = "D";

    private final AuthorizationAdapter authorizationAdapter;
    private final IdentificationAdapter identificationAdapter;
    private final AccessTokenValidator accessTokenValidator;
    private final AttestationKeyProofHandler attestationKeyProofHandler;
    private final JwtKeyProofHandler jwtKeyProofHandler;
    private final CredentialConfigurationIDValidator credentialConfigurationIDValidator;
    private final ResponseEncryptionParameterValidator responseEncryptionParameterValidator;
    private final CredentialRequestDPoPValidator credentialRequestDPoPValidator;
    private final CredentialCreationService credentialCreationService;

    public CredentialService(
        AuthorizationAdapter authorizationAdapter,
        IdentificationAdapter identificationAdapter,
        CredentialConfigurationIDValidator credentialConfigurationIDValidator,
        CredentialRequestDPoPValidator credentialRequestDPoPValidator,
        AccessTokenValidator accessTokenValidator,
        AttestationKeyProofHandler attestationKeyProofHandler,
        JwtKeyProofHandler jwtKeyProofHandler,
        CredentialCreationService credentialCreationService,
        ResponseEncryptionParameterValidator responseEncryptionParameterValidator
    ) {
        this.authorizationAdapter = authorizationAdapter;
        this.identificationAdapter = identificationAdapter;
        this.attestationKeyProofHandler = attestationKeyProofHandler;
        this.jwtKeyProofHandler = jwtKeyProofHandler;
        this.credentialConfigurationIDValidator = credentialConfigurationIDValidator;
        this.credentialRequestDPoPValidator = credentialRequestDPoPValidator;
        this.accessTokenValidator = accessTokenValidator;
        this.credentialCreationService = credentialCreationService;
        this.responseEncryptionParameterValidator = responseEncryptionParameterValidator;
    }

    public CredentialResult processCredentialRequest(CredentialRequest request) {
        var credentials = processRequest(request);
        return new CredentialResult(credentials);
    }

    public CredentialResponseEncryptionResult processCredentialRequestWithResponseEnc(CredentialRequest request) {
        var resEnc = Objects.requireNonNull(request.getCredentialEncryption());
        var resEncAlg = responseEncryptionParameterValidator.validate(resEnc.jwk(), resEnc.enc());
        var credentials = processRequest(request);
        return new CredentialResponseEncryptionResult(credentials, resEnc.jwk(), resEncAlg, resEnc.enc());
    }

    private List<String> processRequest(CredentialRequest request) {
        SignedJWT accessToken = request.getAccessToken();
        var atClaims = accessTokenValidator.validate(accessToken, request.getCredentialConfigurationID());

        String clientID;
        String accessTokenID;
        String seedCredentialRef;
        String refreshTokenRef;
        try {
            clientID = atClaims.getStringClaim(AccessTokenClaims.CLIENT_ID);
            accessTokenID = atClaims.getJWTID();
            seedCredentialRef = atClaims.getStringClaim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE);
            refreshTokenRef = atClaims.getStringClaim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE);
        } catch (ParseException e) {
            throw new IllegalStateException("Could not get claim from validated access token", e);
        }

        JWKThumbprintConfirmation jwkThumbprintConfirmation = JWKThumbprintConfirmation.parse(atClaims);
        Nonce expectedDPoPNonce = authorizationAdapter.getDPoPNonce(accessTokenID);
        try {
            credentialRequestDPoPValidator.validateResourceRequestDPoPProof(accessToken, request.getDpopHeaders(), request.getHttpMethod(), expectedDPoPNonce, jwkThumbprintConfirmation);
        } catch (MissingDPoPNonceException e) {
            Nonce nonce = authorizationAdapter.provideAndStore(accessTokenID);
            throw useDPoPNonce(e.getAcceptedAlgs(), nonce.nonce());
        }
        var seedCredential = authorizationAdapter.retrieveSeedCredential(seedCredentialRef);

        credentialConfigurationIDValidator.validate(request.getCredentialConfigurationID());

        IdentityData originalIdentityData;
        try {
            originalIdentityData = identificationAdapter.verifySeedCredentialAndGetIdentityData(seedCredential);
        } catch (InvalidSeedCredentialException e) {
            log.warn("Seed Credential verification failed. {}", e.getMessage(), e.getCause());
            throw new InvalidIdentityDataException("Seed Credential verification failed.");
        }
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(originalIdentityData);

        if (issuanceDecision instanceof InvalidIssuanceDecision(Set<String> reasons)) {
            log.info("Identity data invalid; reasons: {}", reasons);
            throw new InvalidIdentityDataException("Identity data validation failed.");
        }

        IdentityData identityData = handleDefaultNationality(originalIdentityData);

        List<JWK> jwks = new ArrayList<>();

        jwks.addAll(attestationKeyProofHandler.validateAndGetJwks(request, clientID));
        jwks.addAll(jwtKeyProofHandler.validateAndGetJwks(request, clientID));

        return credentialCreationService.buildCredentials(jwks, identityData, request.getCredentialConfigurationID(), refreshTokenRef);
    }

    private static IdentityData handleDefaultNationality(IdentityData identityData) {
        val nationality = identityData.nationality();
        if (!StringUtils.hasText(nationality) && Objects.equals(identityData.documentType(), DocumentType.ID.name())) {
            return new IdentityData(
                identityData.documentType(),
                identityData.issuingState(),
                identityData.dateOfExpiry(),
                identityData.givenNames(),
                identityData.familyNames(),
                identityData.artisticName(),
                identityData.academicTitle(),
                identityData.dateOfBirth(),
                identityData.placeOfBirth(),
                GERMAN_ID_DEFAULT_NATIONALITY,
                identityData.birthName(),
                identityData.placeOfResidence(),
                identityData.restrictedId());
        } else  {
            return identityData;
        }
    }
}
