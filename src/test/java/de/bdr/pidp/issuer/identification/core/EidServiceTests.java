/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import de.bdr.pidp.issuer.identification.core.seedcredential.SeedCredentialService;
import de.bdr.pidp.issuer.identification.core.seedcredential.SeedException;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialDTO;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialVerificationException;
import de.bdr.pidp.issuer.identification.port.out.IneligibleSeedDecision;
import de.bdr.pidp.issuer.identification.port.out.SeedEligibilityPolicyPort;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;

import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@Slf4j
@SpringBootTest
class EidServiceTests {
    @MockitoSpyBean
    private SeedCredentialService seedCredentialService;
    @MockitoSpyBean
    private SeedEligibilityPolicyPort  seedEligibilityPolicyPort;
    @Autowired
    private EidService eidService;
    @Value("${pidi.identification.server.url}")
    private String eidServerUrl;


    @Test
    void successStartIdentification() throws MalformedURLException, URISyntaxException {
        String issuerState = RandomUtil.randomString();

        var response = eidService.startIdentificationProcess(URI.create("https://redirect.localhost").toURL(), issuerState, null);
        assertThat(response.toString()).startsWith(eidServerUrl + "?SAMLRequest=");
        MultiValueMap<String, String> requestParameters = UriComponentsBuilder.fromUri(response.toURI()).build().getQueryParams();
        var samlRequest = decode(requestParameters.getFirst("SAMLRequest"));
        var relayState = decode(requestParameters.getFirst("RelayState"));
        var sigAlg = decode(requestParameters.getFirst("SigAlg"));
        var signature = decode(requestParameters.getFirst("Signature"));

        log.info("samlRequest: {}", samlRequest);
        log.info("relayState: {}", relayState);
        log.info("sigAlg: {}", sigAlg);
        log.info("signature: {}", signature);
    }


    @Test
    void successVerifySeedCredential() {
        var seedCredentialData = seedCredentialService.createSeedCredential(TEST_IDENTITY_DATA);
        SeedCredentialDTO seedCredentialDTO = eidService.verifySeedCredential(seedCredentialData.seedCredential());
        assertThat(seedCredentialDTO).isNotNull()
            .hasFieldOrPropertyWithValue("seedCredential", seedCredentialData.seedCredential())
            .hasFieldOrPropertyWithValue("jti", seedCredentialData.jti())
            .hasFieldOrPropertyWithValue("sub", seedCredentialData.sub())
            .hasFieldOrPropertyWithValue("exp", seedCredentialData.exp());

        assert seedCredentialData.identityData() != null;
        verify(seedEligibilityPolicyPort).evaluateSeedEligibilityPolicy(seedCredentialData.identityData());
    }

    @Test
    void throwExcerptionWhenVerifySeedCredentialFailed() {
        doThrow(new SeedException("Verification failed")).when(seedCredentialService).verifySeedCredentialAndGetData(anyString());

        assertThatThrownBy(() -> eidService.verifySeedCredential("Seed Credential"))
            .isInstanceOf(SeedCredentialVerificationException.class)
            .hasMessage("Seed credential verification failed");
    }

    @Test
    void throwExcerptionWhenIneligibleSeedDecisionAtVerifySeedCredential() {
        var seedCredentialData = seedCredentialService.createSeedCredential(TEST_IDENTITY_DATA);
        assert seedCredentialData.identityData() != null;
        doReturn(new IneligibleSeedDecision(Set.of("Ineligible identity data")))
            .when(seedEligibilityPolicyPort).evaluateSeedEligibilityPolicy(seedCredentialData.identityData());
        String seedCredential = seedCredentialData.seedCredential();

        assertThatThrownBy(() -> eidService.verifySeedCredential(seedCredential))
            .isInstanceOf(SeedCredentialVerificationException.class)
            .hasMessage("Identity data from Seed Credential are no longer valid");
    }


    @Test
    void throwExcerptionWhenIdentityDataNullAtVerifySeedCredential() {
        var data = seedCredentialService.createSeedCredential(TEST_IDENTITY_DATA);
        doReturn(new SeedCredentialData(data.seedCredential(), null, data.jti(), data.sub(), data.exp()))
            .when(seedCredentialService).verifySeedCredentialAndGetData(anyString());
        String seedCredential = data.seedCredential();

        assertThatThrownBy(() -> eidService.verifySeedCredential(seedCredential))
            .isInstanceOf(SeedCredentialVerificationException.class)
            .hasMessage("Seed Credential does not contain any identity data");
    }

    private static String decode(String enc) {
        return Optional.ofNullable(enc).map(s -> URLDecoder.decode(s, StandardCharsets.UTF_8)).orElse(null);
    }
}
