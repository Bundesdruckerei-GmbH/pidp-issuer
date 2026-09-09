/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.identification.core.configuration.MultiSamlConfiguration;
import de.bdr.pidp.issuer.identification.core.exception.AuthenticationStateException;
import de.bdr.pidp.issuer.identification.core.exception.CryptoConfigException;
import de.bdr.pidp.issuer.identification.core.exception.EidWrappingException;
import de.bdr.pidp.issuer.identification.core.exception.IdentificationError;
import de.bdr.pidp.issuer.identification.core.exception.MissingAuthDataException;
import de.bdr.pidp.issuer.identification.core.exception.SamlCryptoConfigException;
import de.bdr.pidp.issuer.identification.core.exception.SamlResponseValidationFailedException;
import de.bdr.pidp.issuer.identification.core.model.Authentication;
import de.bund.bsi.eid240.PersonalDataType;
import de.governikus.panstar.sdk.saml.configuration.SamlConfiguration;
import de.governikus.panstar.sdk.saml.exception.SamlAuthenticationException;
import de.governikus.panstar.sdk.saml.exception.SamlRequestException;
import de.governikus.panstar.sdk.saml.exception.UnsuccessfulSamlAuthenticationProcessException;
import de.governikus.panstar.sdk.saml.request.SamlRequestGenerator;
import de.governikus.panstar.sdk.saml.response.ProcessedSamlResult;
import de.governikus.panstar.sdk.saml.response.SamlResponseHandler;
import de.governikus.panstar.sdk.utils.RequestData;
import de.governikus.panstar.sdk.utils.constant.SamlError;
import de.governikus.panstar.sdk.utils.exception.InvalidInputException;
import de.governikus.panstar.sdk.utils.saml.SAMLUtils;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.config.InitializationException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
class EidAuthAdapter implements EidAuth {

    private static final String SAML_RESPONSE_COUNTER_METRIC_ID = "saml_response_counter";
    private final MultiSamlConfiguration config;
    private final MultiSamlConfiguration configV2;
    private final Map<SamlConfiguration, SamlRequestGenerator> requestGeneratorMap = new ConcurrentHashMap<>();
    private final Map<SamlConfiguration, SamlResponseHandler> responseHandlerMap = new ConcurrentHashMap<>();
    private final MeterRegistry meterRegistry;

    public EidAuthAdapter(@Qualifier("samlConfigApiV1") MultiSamlConfiguration config,
                          @Qualifier("samlConfigApiV2") MultiSamlConfiguration configV2,
                          MeterRegistry meterRegistry) {
        this.config = config;
        this.configV2 = configV2;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public synchronized String createSamlRedirectBindingUrl(String sessionId, String responseUrl) {

        var requestedData = new RequestData()
            .familyNames(true)
            .givenNames(true)
            .dateOfBirth(true)
            .placeOfBirth(true)
            .restrictedID(true)
            .birthName(true)
            .placeOfResidence(true)
            .nationality(true)
            .documentType(true)
            .artisticName(true)
            .academicTitle(true)
            .issuingState(true)
            .dateOfExpiry(true);

        try {
            var multiConfiguration = findMultiSamlConfiguration(responseUrl);
            // build the SAML request query string that will be sent to the eID-server
            return requestGenerator(multiConfiguration.getConfigurations().getFirst())
                .createSamlRequestUrl(requestedData, sessionId);
        } catch (InvalidInputException | SamlRequestException e) {
            throw new SamlCryptoConfigException("failed to SAML request", true, e);
        }
    }

    private MultiSamlConfiguration findMultiSamlConfiguration(String responseUrl) {
        MultiSamlConfiguration multi;
        if (this.config.getResponseUrl().equals(responseUrl)) {
            multi = this.config;
        } else if (this.configV2.getResponseUrl().equals(responseUrl)) {
            multi = this.configV2;
        } else {
            throw new IllegalArgumentException("unexpected responseURL: " + responseUrl);
        }
        return multi;
    }

    private SamlRequestGenerator requestGenerator(SamlConfiguration samlConfiguration) {
        var requestGenerator = this.requestGeneratorMap.get(samlConfiguration);
        if (requestGenerator == null) {
            try {
                requestGenerator = new SamlRequestGenerator(samlConfiguration);
                this.requestGeneratorMap.put(samlConfiguration, requestGenerator);
            } catch (InitializationException | InvalidInputException | SamlRequestException e) {
                throw new CryptoConfigException("failed to initialize PanStar SDK", e);
            }
        }
        return requestGenerator;
    }

    private ProcessedSamlResult validateAndExtractAttributes(String samlResponse, String relayState, String sigAlg, String signature, String responseUrl) {
        ProcessedSamlResult result;
        var samlConfiguration = validateCertificatesAgainstQuery(responseUrl, samlResponse, relayState, sigAlg, signature);
        try {
            result = responseHandler(samlConfiguration).parseSamlResponse(samlResponse, relayState, signature, sigAlg);
        } catch (SamlAuthenticationException | InvalidInputException e) {
            incrementFailureCounter(null);
            throw new SamlResponseValidationFailedException("could not decode the SAML Response", null, e);
        } catch (UnsuccessfulSamlAuthenticationProcessException e) {
            throw toSamlResponseValidationFailedException(e, "could not resolve the SAML Response");
        }
        incrementSuccessCounter();
        return result;
    }

    /**
     * validate the signature of the SAML response against the configured certificates and selects the matching one
     * (per ThreadLocal).
     *
     * @param responseUrl  on which URL was the response received
     * @param samlResponse the <em>SAMLResponse</em> query parameter
     * @param relayState   the <em>RelayState</em> query parameter, may be <code>null</code>
     * @param sigAlg       the <em>SigAlg</em> query parameter
     * @param signature    the <em>Signature</em> query parameter
     * @return the <code>SamlConfiguration</code> that was successful in verifying the signature
     * @throws SamlCryptoConfigException or SamlResponseValidationFailedException if the response could not be verified
     *                                   and increases the failure counter
     */
    private SamlConfiguration validateCertificatesAgainstQuery(String responseUrl, String samlResponse, String relayState, String sigAlg, String signature) {
        var multi = findMultiSamlConfiguration(responseUrl);
        for (var configuration : multi.getConfigurations()) {
            if (SAMLUtils.checkQuerySignature(samlResponse, relayState, sigAlg, signature,
                configuration.getSamlKeyMaterial().getSamlResponseSignatureValidatingCertificate(), false)) {
                return configuration;
            }
        }
        throw toSamlResponseValidationFailedException(null, "no certificate found that validates signature");
    }

    private SamlResponseHandler responseHandler(SamlConfiguration samlConfiguration) {
        return Optional.ofNullable(this.responseHandlerMap.get(samlConfiguration)).orElseGet(() -> {
            try {
                var responseHandler = new SamlResponseHandler(samlConfiguration);
                storeResponseHandlerForConfiguration(samlConfiguration, responseHandler);
                return responseHandler;
            } catch (InitializationException | InvalidInputException e) {
                throw new CryptoConfigException("failed to initialize PanStar SDK", e);
            }
        });
    }

    void storeResponseHandlerForConfiguration(SamlConfiguration samlConfiguration, SamlResponseHandler responseHandler) {
        this.responseHandlerMap.put(samlConfiguration, responseHandler);
    }

    private SamlResponseValidationFailedException toSamlResponseValidationFailedException(UnsuccessfulSamlAuthenticationProcessException e, String message) {
        var visibleCode = translateSamlStatusCodeToOurVisibleCode(e).map(IdentificationError::toString).orElse(EidWrappingException.ERR_CODE_SYSTEM);

        incrementFailureCounter(e == null ? null : e.getSamlError());
        return new SamlResponseValidationFailedException(message, visibleCode, e);
    }

    private void incrementSuccessCounter() {
        incrementResponseCounter(true, null);
    }

    private void incrementFailureCounter(SamlError samlError) {
        incrementResponseCounter(false, samlError);
    }

    private void incrementResponseCounter(boolean success, SamlError samlError) {
        this.meterRegistry.counter(SAML_RESPONSE_COUNTER_METRIC_ID, toTags(success, samlError)).increment();
    }

    private Iterable<Tag> toTags(boolean success, SamlError samlError) {
        String statusCode = "N/A";
        String minorCode = "N/A";
        if (!success) {
            if (samlError != null) {
                statusCode = samlError.getTopLevelStatusCode();
                minorCode = samlError.getSecondLevelStatusCode();
            } else {
                statusCode = EidWrappingException.ERR_CODE_SYSTEM;
            }
        }
        return Tags.of(
            "success", String.valueOf(success),
            "statusCode", statusCode,
            "minorCode", minorCode
        );
    }

    Optional<IdentificationError> translateSamlStatusCodeToOurVisibleCode(UnsuccessfulSamlAuthenticationProcessException e) {
        if (e == null || e.getSamlError() == null) {
            return Optional.empty();
        }
        log.warn("SamlResponse Status Code {}", e.getSamlError());
        return Optional.of(SamlCodeTranslations.getPidiError(e.getSamlError()));
    }

    @Override
    public PersonalDataType validateSamlResponseAndExtractPseudonym(String relayState, String samlResponse, String sigAlg,
                                                                    String signature, String responseUrl,
                                                                    Authentication authentication) {
        ProcessedSamlResult processed =
            validateAndExtractAttributes(samlResponse, relayState, sigAlg, signature, responseUrl);
        validateEidResponse(processed);
        if (!relayState.equals(authentication.getSamlId())) {
            throw new AuthenticationStateException("SAML ID from Authentication did not match the relayState");
        }
        return processed.getPersonalData();
    }

    void validateEidResponse(ProcessedSamlResult processed) {
        if (processed == null) {
            throw new MissingAuthDataException("the SAML Response did not include the attributes");
        }
        log.debug("from processed response:  inResponseTo={}, samlResponseId={}",
            processed.getInResponseTo(), processed.getSamlResponseID());
    }
}
