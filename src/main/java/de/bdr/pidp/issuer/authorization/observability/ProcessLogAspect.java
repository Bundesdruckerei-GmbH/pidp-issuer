/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import de.bdr.pidp.issuer.base.logging.ProcessLog;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Aspect
@Slf4j
@Component("authProcessLogAspect")
public class ProcessLogAspect extends ProcessLog {

    @Override
    @Before("execution(* de.bdr.pidp.issuer.authorization.in.OAuthController.*(..))")
    public void logProcessIncoming() {
        super.logProcessIncoming();
    }

    @Override
    @AfterReturning(
        pointcut = """
            execution(* de.bdr.pidp.issuer.authorization.in.OAuthController.*(..)) || \
            execution(* de.bdr.pidp.issuer.authorization.in.OAuthExceptionHandler.*(..))""",
        returning = "result"
    )
    public void logProcessOutgoing(ResponseEntity<?> result) {
        super.logProcessOutgoing(result);
    }
}
