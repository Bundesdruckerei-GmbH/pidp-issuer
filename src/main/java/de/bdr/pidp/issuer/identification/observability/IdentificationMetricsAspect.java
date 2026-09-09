/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.observability;

import de.bdr.pidp.issuer.base.VerificationResult;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

@Aspect
@Component
class IdentificationMetricsAspect {

    private final Counter identificationStartedCounter;
    private final Counter identificationCompletedCounter;

    IdentificationMetricsAspect(MeterRegistry meterRegistry) {
        this.identificationStartedCounter = Counter.builder("identification.started")
            .description("Number of identification processes started")
            .register(meterRegistry);

        this.identificationCompletedCounter = Counter.builder("identification.completed")
            .description("Number of identification processes completed successfully")
            .register(meterRegistry);
    }

    @Before("execution(* de.bdr.pidp.issuer.identification.port.in.IdentificationDataPortIn.startIdentificationProcess(..))")
    void countIdentificationStarted() {
        identificationStartedCounter.increment();
    }

    @AfterReturning(
        pointcut = "execution(* de.bdr.pidp.issuer.identification.port.in.IdentificationDataPortIn.checkIdentification(..))",
        returning = "result"
    )
    void countIdentificationCompleted(@Nullable VerificationResult result) {
        if (result != null && !result.status().isError()) {
            identificationCompletedCounter.increment();
        }
    }
}
