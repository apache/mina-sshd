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
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.filter.BufferInputHandler;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.DefaultIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * A filter implementing "delayed KEX-INIT" where the client waits for the server's initial KEX-INIT to arrive first
 * before sending its own.
 */
public class DelayKexInitFilter extends IoFilter {

    private AtomicBoolean isFirst = new AtomicBoolean(true);

    private final DefaultIoWriteFuture initReceived = new DefaultIoWriteFuture(this, null);

    private final AtomicReference<InputHandler> input = new AtomicReference<>();

    private final AtomicReference<OutputHandler> output = new AtomicReference<>();

    private Session session;

    public DelayKexInitFilter() {
        input.set(new KexInputHandler());
        output.set(new KexOutputHandler());
    }

    @Override
    public InputHandler in() {
        return input.get();
    }

    @Override
    public OutputHandler out() {
        return output.get();
    }

    public void setSession(Session session) {
        this.session = Objects.requireNonNull(session);
    }

    private class KexInputHandler implements BufferInputHandler {

        KexInputHandler() {
            super();
        }

        @Override
        public void handleMessage(Buffer message) throws Exception {
            if (input.get() != null) {
                int cmd = message.rawByte(message.rpos());
                if (cmd == SshConstants.SSH_MSG_KEXINIT) {
                    initReceived.setValue(Boolean.TRUE);
                    input.set(null);
                }
            }
            owner().passOn(message);
        }

    }

    private class KexOutputHandler implements OutputHandler {

        KexOutputHandler() {
            super();
        }

        @Override
        public IoWriteFuture send(Buffer message) throws IOException {
            if (output.get() == null) {
                return owner().send(message);
            }
            int cmd = message.rawByte(message.rpos());
            if (cmd != SshConstants.SSH_MSG_KEXINIT) {
                return owner().send(message);
            }
            boolean first = isFirst.getAndSet(false);
            if (!first || session.isServerSession()
                    || CoreModuleProperties.SEND_IMMEDIATE_KEXINIT.getRequired(session).booleanValue()) {
                return owner().send(message).addListener(f -> output.set(null));
            }
            // We're a client, and we delay sending the initial KEX-INIT until we have received the peer's KEX-INIT
            IoWriteFuture initial = owner().send(null);
            DefaultIoWriteFuture result = new DefaultIoWriteFuture(KexOutputHandler.this, null);
            initial.addListener(init -> {
                Throwable t = init.getException();
                if (t != null) {
                    result.setValue(t);
                    return;
                }
                initReceived.addListener(f -> {
                    try {
                        owner().send(message).addListener(g -> {
                            output.set(null);
                            result.setValue(g.isWritten() ? Boolean.TRUE : g.getException());
                        });
                    } catch (IOException e) {
                        result.setValue(e);
                    }
                });
            });
            return result;
        }

    }
}
