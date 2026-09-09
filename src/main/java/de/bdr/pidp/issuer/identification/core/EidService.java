/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.identification.core.configuration.InfoConfiguration;
import de.bdr.pidp.issuer.identification.core.configuration.Tr03124Configuration;
import de.bdr.pidp.issuer.identification.core.exception.SamlResponseValidationFailedException;
import de.bdr.pidp.issuer.identification.core.model.Authentication;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import de.bdr.pidp.issuer.identification.core.seedcredential.EidDataMapper;
import de.bdr.pidp.issuer.identification.core.seedcredential.SeedCredentialService;
import de.bdr.pidp.issuer.identification.out.persistence.EIDResultAdapter;
import de.bdr.pidp.issuer.identification.port.in.IdentificationDataPortIn;
import de.bdr.pidp.issuer.identification.port.in.ReceiveEidDataPortIn;
import de.bdr.pidp.issuer.identification.port.in.ResourceDoesNotExistException;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialDTO;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialVerificationException;
import de.bdr.pidp.issuer.identification.port.out.EligibleSeedDecision;
import de.bdr.pidp.issuer.identification.port.out.IneligibleSeedDecision;
import de.bdr.pidp.issuer.identification.port.out.SeedEligibilityDecision;
import de.bdr.pidp.issuer.identification.port.out.SeedEligibilityPolicyPort;
import io.micrometer.core.annotation.Timed;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.NoSuchElementException;
import java.util.Set;

@NullMarked
@Slf4j
@Service
class EidService implements IdentificationDataPortIn, ReceiveEidDataPortIn {

    private static final String MDC_SESSION_ID = "sessionId";

    private final AuthenticationService authenticationService;
    private final Tr03124Configuration tr03124Configuration;
    private final IdentificationConfiguration identificationConfiguration;
    private final EIDResultAdapter eIDResultAdapter;
    private final SeedCredentialService seedCredentialService;
    private final SeedEligibilityPolicyPort seedEligibilityPolicyPort;
    private final EidDataMapper mapper;

    public EidService(AuthenticationService authenticationService,
                      @Qualifier("infoV2") InfoConfiguration infoConfiguration,
                      EIDResultAdapter eIDResultAdapter, IdentificationConfiguration identificationConfiguration,
                      SeedCredentialService seedCredentialService, SeedEligibilityPolicyPort seedEligibilityPolicyPort) {
        this.authenticationService = authenticationService;
        this.tr03124Configuration = infoConfiguration;
        this.identificationConfiguration = identificationConfiguration;
        this.eIDResultAdapter = eIDResultAdapter;
        this.seedCredentialService = seedCredentialService;
        this.mapper = new EidDataMapper(identificationConfiguration.getCredentialIssuerIdentifier());
        this.seedEligibilityPolicyPort = seedEligibilityPolicyPort;
    }

    @Timed
    public URL startIdentificationProcess(URL redirectUrl, String issuerState, @Nullable String sessionId) {
        Authentication auth = authenticationService.initializeAuthentication(issuerState, redirectUrl, sessionId);
        var authToken = auth.getTokenId();
        var responseUrl = tr03124Configuration.createSamlConsumerUrl();
        var samlRedirectUrl = authenticationService.createSamlRedirectBindingUrl(authToken, responseUrl);
        try {
            return URI.create(samlRedirectUrl).toURL();
        } catch (MalformedURLException e) {
            throw new PidServerException("malformed url", e);
        }
    }

    public URL processSamlResponse(String saMLResponse, String relayState, String sigAlg, String signature) {
        var authentication = authenticationService.loadBySamlId(relayState);
        MDC.put(MDC_SESSION_ID, authentication.getSessionId());
        try {
            var identityData = mapper.map(authenticationService.receiveSamlResponse(relayState, saMLResponse, sigAlg, signature, tr03124Configuration.createSamlConsumerUrl()));
            SeedEligibilityDecision seedEligibilityDecision = seedEligibilityPolicyPort.evaluateSeedEligibilityPolicy(identityData);
            switch (seedEligibilityDecision) {
                case EligibleSeedDecision _ -> {
                    var seedCredentialData = seedCredentialService.createSeedCredential(identityData);

                    if (identificationConfiguration.isLoggingPseudonymsAllowed()) {
                        log.debug("received {}", identityData);
                    }
                    eIDResultAdapter.storeIdentification(authentication.getExternalId(), seedCredentialData);
                }
                case IneligibleSeedDecision(Set<String> reasons) -> {
                    log.info("Identity data not eligible, Validation errors: {}", reasons);
                    eIDResultAdapter.storeIdentificationError(authentication.getExternalId(), "Identity data not eligible.");
                }
            }
        } catch (Exception e) {
            log.info("Failure in eID identification {}", authentication.getExternalId(), e);
            if (e instanceof SamlResponseValidationFailedException samlResponseValidationFailedException) {
                log.warn("Reason for failure in eID identification {}: {}", authentication.getExternalId(), samlResponseValidationFailedException.getVisibleCode());
            }
            eIDResultAdapter.storeIdentificationError(authentication.getExternalId(), e.getMessage());
        }
        return authentication.getRedirectUrl();
    }

    @Override
    public VerificationResult checkIdentification(String externalId) {
        try {
            return eIDResultAdapter.checkIdentification(externalId);
        } catch (NoSuchElementException e) {
            throw new ResourceDoesNotExistException("Could not find eID result", e);
        }
    }

    @Override
    public SeedCredentialDTO collectEncryptedIdentification(String externalId) {
        SeedCredentialData seedCredentialData;
        try {
            seedCredentialData = eIDResultAdapter.getAndDeleteIdentification(externalId);
        } catch (NoSuchElementException e) {
            throw new ResourceDoesNotExistException("Could not collect eID data", e);
        }
        return mapSeedCredentialData(seedCredentialData);
    }

    @Override
    public SeedCredentialDTO verifySeedCredential(String seedCredential) {
        SeedCredentialData seedCredentialData;
        try {
            seedCredentialData = seedCredentialService.verifySeedCredentialAndGetData(seedCredential);
        } catch (Exception e) {
            throw new SeedCredentialVerificationException("Seed credential verification failed", e);
        }
        if (seedCredentialData.identityData() != null) {
            SeedEligibilityDecision seedEligibilityDecision = seedEligibilityPolicyPort.evaluateSeedEligibilityPolicy(seedCredentialData.identityData());
            return switch (seedEligibilityDecision) {
                case EligibleSeedDecision _ -> mapSeedCredentialData(seedCredentialData);
                case IneligibleSeedDecision(Set<String> reasons) -> {
                    log.info("Identity Data are no longer valid. Reasons: {}", reasons);
                    throw new SeedCredentialVerificationException("Identity data from Seed Credential are no longer valid");
                }
            };
        } else  {
            throw new SeedCredentialVerificationException("Seed Credential does not contain any identity data");
        }
    }

    @Override
    public IdentityData verifySeedCredentialAndGetIdentitydata(String seedCredential) {
        IdentityData identityData = seedCredentialService.verifySeedCredentialAndGetData(seedCredential).identityData();
        if  (identityData == null) {
            throw new SeedCredentialVerificationException("Seed Credential does not contain any identity data");
        }
        return identityData;
    }

    private SeedCredentialDTO mapSeedCredentialData(SeedCredentialData seedCredentialData) {
        return new SeedCredentialDTO(seedCredentialData.seedCredential(), seedCredentialData.jti(), seedCredentialData.sub(), seedCredentialData.exp());
    }
}
