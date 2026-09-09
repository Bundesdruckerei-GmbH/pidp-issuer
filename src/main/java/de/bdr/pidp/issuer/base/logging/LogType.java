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
public class LogType {
    public static final String MDC_KEY = "logType";

    public static MDC.MDCCloseable mdcContext(Value logTypeValue) {
        return MDC.putCloseable(MDC_KEY, logTypeValue.name);
    }

    @RequiredArgsConstructor
    public enum Value {
        SECURITY("security");

        @Getter
        private final String name;
    }
}
