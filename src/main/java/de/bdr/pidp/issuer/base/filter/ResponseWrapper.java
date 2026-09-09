/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.filter;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class ResponseWrapper extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private final PrintWriter writer = new PrintWriter(new OutputStreamWriter(outputStream));

    public ResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() {
        return new ServletOutputStream() {
            @Override
            public boolean isReady() {
                // Indicate whether the stream is ready to be written to.
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
                // No-op for synchronous processing
            }

            @Override
            public void write(int b) {
                outputStream.write(b);
            }
        };
    }

    @Override
    public PrintWriter getWriter() {
        // Use PrintWriter to capture text data
        return writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        super.flushBuffer();
        writer.flush();
    }

    public byte[] getResponseData() {
        writer.flush();
        return outputStream.toByteArray();
    }
}
