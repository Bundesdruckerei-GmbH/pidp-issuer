/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.logging;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class LogCategory {
    public static final String MDC_KEY = "bop.app.category";

    public static MDC.MDCCloseable mdcContext(LogCategory.Value logCategoryValue) {
        return MDC.putCloseable(MDC_KEY, logCategoryValue.name);
    }

    @RequiredArgsConstructor
    public enum Value {
        PROCESS("process");

        @Getter
        private final String name;
    }
}
