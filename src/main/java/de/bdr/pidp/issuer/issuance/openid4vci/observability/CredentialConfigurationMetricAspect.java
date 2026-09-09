/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import de.bdr.pidp.issuer.issuance.openid4vci.exception.UnknownCredentialConfigurationException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

@NullMarked
@Aspect
@Component
public class CredentialConfigurationMetricAspect {

    private final CredentialConfigurationMetricMonitor credentialConfigurationMetricMonitor;

    public CredentialConfigurationMetricAspect(CredentialConfigurationMetricMonitor credentialConfigurationMetricMonitor) {
        this.credentialConfigurationMetricMonitor = credentialConfigurationMetricMonitor;
    }

    @Before("""
        (\
        execution(* de.bdr.pidp.issuer.issuance.openid4vci.service.CredentialService.processCredentialRequest(..)) || \
        execution(* de.bdr.pidp.issuer.issuance.openid4vci.service.CredentialService.processCredentialRequestWithResponseEnc(..))\
        ) && \
        args(request)""")
    public void logCredentialConfigurationId(CredentialRequest request) {
        credentialConfigurationMetricMonitor.recordUsage(request.getCredentialConfigurationID());
    }

    @Before("execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.OpenID4VCIExceptionHandler.handleUnknownCredentialConfigurationException(..)) && args(exception)")
    public void logCredentialConfigurationId(UnknownCredentialConfigurationException exception) {
        credentialConfigurationMetricMonitor.recordUsage(exception.getCredentialConfigurationId());
    }
}
