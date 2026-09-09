/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import de.bdr.pidp.issuer.base.logging.LogCategory;
import de.bdr.pidp.issuer.base.logging.ProcessLog;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.JsonNode;

import static de.bdr.pidp.issuer.base.logging.LogCategory.Value.PROCESS;

@Slf4j
@Aspect
@Component
public class ProcessLogAspect extends ProcessLog {

    @Override
    @Before("""
        (
        execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.CredentialController.issueCredential(.., @org.springframework.web.bind.annotation.RequestBody (*), ..)) || \
        execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.CredentialController.issueCredentialEnc(.., @org.springframework.web.bind.annotation.RequestBody (*), ..))
        ) && \
        args(.., requestBody)""")
    public void logProcessIncoming(Object requestBody) {
        super.logProcessIncoming(requestBody);
    }

    @Override
    @Before("execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.CredentialController.issueNonce(..)))")
    public void logProcessIncoming() {
        super.logProcessIncoming();
    }

    @Override
    @AfterReturning(
        pointcut = """
            execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.CredentialController.issueNonce(..)) || \
            execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.OpenID4VCIExceptionHandler.*(..))""",
        returning = "result"
    )
    public void logProcessOutgoing(ResponseEntity<?> result) {
        super.logProcessOutgoing(result);
    }

    /**
     * credential endpoint process log should not log the credentials themselves
     */
    @AfterReturning(
        pointcut = """
            execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.CredentialController.issueCredential(..)) || \
            execution(* de.bdr.pidp.issuer.issuance.openid4vci.in.CredentialController.issueCredentialEnc(..))""",
        returning = "result"
    )
    public void logProcessCredentialOutgoing(ResponseEntity<?> result) {
        var attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return;
        }
        var request = attributes.getRequest();

        var body = result.getBody();
        if (body == null) {
            return;
        }
        var details = switch (body) {
            case JsonNode node -> countCredentialsIssued(node);
            case String _ -> "response body is encrypted";
            default -> null;
        };
        if (details == null) {
            return;
        }

        try (var _ = LogCategory.mdcContext(PROCESS)) {
            log.info(
                "Outgoing response {} {} with status {}, {}, headers: {}",
                request.getMethod(),
                request.getRequestURI(),
                result.getStatusCode(),
                details,
                jsonMapper.writeValueAsString(result.getHeaders().headerSet())
            );
        }
    }

    private String countCredentialsIssued(JsonNode body) {
        if (body == null) {
            return null;
        }
        var found = body.findValue("credentials");
        if (found == null || !found.isArray()) {
            return null;
        }
        var count = found.asArray().size();

        return "issued " + count + " credentials";
    }
}
