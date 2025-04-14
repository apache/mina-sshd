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
package org.apache.sshd.client.session.filter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.client.session.AbstractClientSession;
import org.apache.sshd.client.session.proxy.AbstractProxyConnector;
import org.apache.sshd.client.session.proxy.HttpProxyConnector;
import org.apache.sshd.client.session.proxy.Socks5ProxyConnector;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.DefaultIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A filter implementing the client-side proxy protocol for tunneling through a SOCKS or HTTP CONNECT proxy. Supports
 * SOCKS 5 with anonymous access or password or Kerberos 5 authentication, or HTTP CONNECT with anonymous, basic, or
 * SPNEGO authentication.
 */
public class ClientProxyFilter extends IoFilter {

    private final AbstractClientSession session;

    private final AbstractProxyConnector connector;

    private final AtomicReference<InputHandler> input = new AtomicReference<>();

    private final AtomicReference<OutputHandler> output = new AtomicReference<>();

    // We need to be able to queue one, at most two messages: the SSH protocol version message, and the initial
    // KEX-INIT.
    private final Queue<Runnable> queue = new ConcurrentLinkedQueue<>();

    private final SshFutureListener<CloseFuture> closer;

    public ClientProxyFilter(AbstractClientSession session, ProxyData proxy, InetSocketAddress targetAddress) {
        this.session = Objects.requireNonNull(session);
        connector = proxy.getType() == Proxy.Type.SOCKS
                ? new Socks5ProxyConnector(proxy, targetAddress, this::write, this::proxyAuth)
                : new HttpProxyConnector(proxy, targetAddress, this::write, this::proxyAuth);
        closer = f -> connector.close();
        session.getIoSession().addCloseFutureListener(closer);
        input.set(new ProxyInputHandler());
        output.set(new ProxyOutputHandler());
    }

    @Override
    public InputHandler in() {
        return input.get();
    }

    @Override
    public OutputHandler out() {
        return output.get();
    }

    // Callback for the connector
    private IoWriteFuture write(Buffer message) throws IOException {
        return owner().send(-1, message);
    }

    private PasswordAuthentication proxyAuth(InetSocketAddress proxyAddress) {
        UserInteraction ui = session.getUserInteraction();
        if (ui == null) {
            return null;
        }
        return ui.getProxyCredentials(session, proxyAddress);
    }

    private class ProxyInputHandler implements InputHandler {

        ProxyInputHandler() {
            super();
        }

        @Override
        public void received(Readable message) throws Exception {
            if (input.get() == null || connector.isDone()) {
                owner().passOn(message);
            } else {
                Buffer buffer = connector.received(message);
                if (connector.isDone()) {
                    session.getIoSession().removeCloseFutureListener(closer);
                    connector.close();
                    if (buffer != null && buffer.available() > 0) {
                        buffer.compact();
                        owner().passOn(buffer);
                    }
                    input.set(null);
                    synchronized (queue) {
                        output.set(null);
                        for (;;) {
                            Runnable send = queue.poll();
                            if (send == null) {
                                break;
                            }
                            send.run();
                        }
                    }
                }
            }
        }
    }

    private class ProxyOutputHandler implements OutputHandler {

        private AtomicBoolean first = new AtomicBoolean(true);

        ProxyOutputHandler() {
            super();
        }

        @Override
        public IoWriteFuture send(int cmd, Buffer message) throws IOException {
            if (first.compareAndSet(true, false)) {
                connector.start();
            }
            synchronized (queue) {
                if (output.get() != null) {
                    DefaultIoWriteFuture result = new DefaultIoWriteFuture(this, null);
                    queue.add(() -> {
                        try {
                            owner().send(cmd, message).addListener(w -> {
                                result.setValue(w.isWritten() ? Boolean.TRUE : w.getException());
                            });
                        } catch (IOException e) {
                            result.setValue(e);
                        }
                    });
                    return result;
                }
            }
            return owner().send(cmd, message);
        }

    }
}
