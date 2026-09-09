/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.identification.core.model.Authentication;
import de.bund.bsi.eid240.PersonalDataType;

public interface EidAuth {

    String createSamlRedirectBindingUrl(String samlId, String responseUrl);

    /**
     * @param relayState     from SAML, used to correlate response to request
     * @param samlResponse   from SAML
     * @param sigAlg         the Signature algorithm
     * @param signature      the Signature
     * @param responseUrl
     * @param authentication the Authentication that contains the SAML identifier (to be compared with SAML response)
     * @return extracted data from samlResponse
     */
    PersonalDataType validateSamlResponseAndExtractPseudonym(String relayState, String samlResponse, String sigAlg, String signature, String responseUrl, Authentication authentication);

}
