/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.session.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.DefaultIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * A filter for sending the identification string before the first outgoing packet, and for receiving the peer's
 * identification. Once both idents have been sent and received the filter removes itself from the filter chain.
 */
public class IdentFilter extends IoFilter {

    private static final String CRLF = "\r\n";

    private DefaultIoWriteFuture received = new DefaultIoWriteFuture("IdentReceived", null);

    private PropertyResolver properties;

    private SshIdentHandler identHandler;

    private final AtomicReference<InputHandler> readHandler = new AtomicReference<>();

    private final AtomicReference<OutputHandler> writeHandler = new AtomicReference<>();

    public IdentFilter() {
        super();
    }

    @Override
    public void adding(FilterChain chain) {
        super.adding(chain);
        readHandler.set(new ReadHandler());
        writeHandler.set(new WriteHandler());
    }

    public void setIdentHandler(SshIdentHandler handler) {
        identHandler = handler;
    }

    public void setPropertyResolver(PropertyResolver resolver) {
        properties = resolver;
    }

    @Override
    public InputHandler in() {
        return readHandler.get();
    }

    @Override
    public OutputHandler out() {
        return writeHandler.get();
    }

    private class ReadHandler implements InputHandler {

        private final ByteArrayBuffer buffer = new ByteArrayBuffer();

        private boolean haveIdent;

        ReadHandler() {
            super();
        }

        @Override
        public synchronized void received(Readable message) throws Exception {
            if (haveIdent) {
                // Something called IdentFilter.in() and got this ReadHandler before we could set it to null below.
                // Just pass on the message.
                owner().passOn(IdentFilter.this, message);
            } else {
                buffer.putBuffer(message);
                List<String> lines = identHandler.readIdentification(buffer);
                haveIdent = !GenericUtils.isEmpty(lines);
                if (haveIdent) {
                    buffer.compact();
                    received.setValue(Boolean.TRUE);
                    if (buffer.available() > 0) {
                        owner().passOn(IdentFilter.this, buffer);
                    }
                    readHandler.set(null);
                    if (writeHandler.get() == null) {
                        owner().remove(IdentFilter.this);
                    }
                }
            }
        }

    }

    private class WriteHandler implements OutputHandler {

        private final AtomicBoolean firstMessage = new AtomicBoolean(true);

        /*
         * Just in case that send gets called again before the first message has gone out: queue up further messages via
         * a listener on the last outgoing message's IoWriteFuture, and set the new last to the new future.
         *
         * Otherwise it would be possible that a second message actually gets out before the first one it sent.
         *
         * In practice this should not occur if the KexFilter only proceeds with KEX once it has received the peeer's
         * KEX_INIT and it's own KEX_INIT indeed has been written (i.e., it's future is fulfilled).
         *
         * The alternative would be not to queue up sending the ident and the first message via futures. We could just
         * call owner().send() twice, ignoring the future of the first one, and rely on the fact that the transports
         * (NIO2, MINA, Netty) all have their own queue. But that might mean that an exception reported through the
         * future of the first send might be ignored.
         */
        private final AtomicReference<IoWriteFuture> lastWrite = new AtomicReference<>();

        WriteHandler() {
            super();
        }

        @Override
        public IoWriteFuture send(Buffer message) throws IOException {
            boolean isFirst = firstMessage.getAndSet(false);
            if (isFirst) {
                IoWriteFuture identSent;
                if (identHandler.isServer()
                        || CoreModuleProperties.SEND_IMMEDIATE_IDENTIFICATION.getRequired(properties).booleanValue()) {
                    identSent = owner().send(IdentFilter.this, getIdent());
                } else {
                    // We're a client, and we wait for the server's ident to arrive first.
                    DefaultIoWriteFuture delayed = new DefaultIoWriteFuture("DelayedIdent", null);
                    identSent = delayed;
                    received.addListener(identReceived -> {
                        try {
                            owner().send(IdentFilter.this, getIdent()).addListener(idSent -> {
                                delayed.setValue(idSent.isWritten() ? Boolean.TRUE : idSent.getException());
                            });
                        } catch (IOException e) {
                            delayed.setValue(e);
                        }
                    });
                }
                lastWrite.set(identSent);
                if (message == null) {
                    // Special case: KEX filter has decided to wait with its KEX_INIT until it has received the peer's.
                    // To trigger sending the ident, it passes a null message.
                    identSent.addListener(f -> lastWrite.compareAndSet(identSent, null));
                    return identSent;
                }
            }
            IoWriteFuture queue = lastWrite.get();
            if (queue == null || queue.isDone()) {
                lastWrite.set(null);
                IoWriteFuture result = owner().send(IdentFilter.this, message);
                writeHandler.set(null);
                if (readHandler.get() == null) {
                    owner().remove(IdentFilter.this);
                }
                return result;
            }
            DefaultIoWriteFuture result = new DefaultIoWriteFuture("Ident", null);
            lastWrite.compareAndSet(queue, result);
            queue.addListener(f -> {
                lastWrite.compareAndSet(result, null);
                if (f.isWritten()) {
                    try {
                        owner().send(IdentFilter.this, message).addListener(msgSent -> {
                            result.setValue(msgSent.isWritten() ? Boolean.TRUE : msgSent.getException());
                        });
                    } catch (IOException e) {
                        result.setValue(e);
                    }
                } else {
                    result.setValue(f.getException());
                }
            });
            return result;
        }

        private Buffer getIdent() {
            List<String> ident = identHandler.provideIdentification();
            if (GenericUtils.isEmpty(ident) || (!identHandler.isServer() && GenericUtils.size(ident) > 1)) {
                throw new IllegalStateException("Invalid SSH protocol version " + ident);
            }
            String myIdentification = ident.stream().collect(Collectors.joining(CRLF)) + CRLF;
            return new ByteArrayBuffer((myIdentification).getBytes(StandardCharsets.UTF_8));
        }
    }
}
