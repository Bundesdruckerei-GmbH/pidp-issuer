/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config;

import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.core.service.CredentialCreator;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV1;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV2;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV3Beta;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV1;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV2;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV3Beta;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PidDataBuilderConfig.class)
class PidDataBuilderConfigTest {

    @Autowired
    private Map<CredentialConfigurationID, CredentialCreator> credentialCreators;

    @Autowired
    private SdJwtCredentialCreatorV1 sdJwtV1;
    @Autowired
    private SdJwtCredentialCreatorV2 sdJwtV2;
    @Autowired
    private SdJwtCredentialCreatorV3Beta sdJwtV3b;
    @Autowired
    private MdocCredentialCreatorV1 mdocV1;
    @Autowired
    private MdocCredentialCreatorV2 mdocV2;
    @Autowired
    private MdocCredentialCreatorV3Beta mdocV3b;

    @Test
    void shouldInitializeAllBeansAndMapThemCorrectlyInContext() {
        // Verify individual beans are initialized
        assertThat(sdJwtV1).isNotNull();
        assertThat(sdJwtV2).isNotNull();
        assertThat(sdJwtV3b).isNotNull();
        assertThat(mdocV1).isNotNull();
        assertThat(mdocV2).isNotNull();
        assertThat(mdocV3b).isNotNull();

        // Verify the Map bean contains exactly the same instances as the individual beans
        assertThat(credentialCreators)
            .hasSize(6)
            .containsEntry(CredentialConfigurationID.SD_JWT_V1, sdJwtV1)
            .containsEntry(CredentialConfigurationID.SD_JWT_V2, sdJwtV2)
            .containsEntry(CredentialConfigurationID.SD_JWT_V3_BETA, sdJwtV3b)
            .containsEntry(CredentialConfigurationID.MSO_MDOC_V1, mdocV1)
            .containsEntry(CredentialConfigurationID.MSO_MDOC_V2, mdocV2)
            .containsEntry(CredentialConfigurationID.MSO_MDOC_V3_BETA, mdocV3b);

        assertThat(credentialCreators.get(CredentialConfigurationID.SD_JWT_V1)).isInstanceOf(SdJwtCredentialCreatorV1.class);
        assertThat(credentialCreators.get(CredentialConfigurationID.SD_JWT_V2)).isInstanceOf(SdJwtCredentialCreatorV2.class);
        assertThat(credentialCreators.get(CredentialConfigurationID.SD_JWT_V3_BETA)).isInstanceOf(SdJwtCredentialCreatorV3Beta.class);
        assertThat(credentialCreators.get(CredentialConfigurationID.MSO_MDOC_V1)).isInstanceOf(MdocCredentialCreatorV1.class);
        assertThat(credentialCreators.get(CredentialConfigurationID.MSO_MDOC_V2)).isInstanceOf(MdocCredentialCreatorV2.class);
        assertThat(credentialCreators.get(CredentialConfigurationID.MSO_MDOC_V3_BETA)).isInstanceOf(MdocCredentialCreatorV3Beta.class);
    }
}
