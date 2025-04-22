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
package org.apache.sshd.contrib.server.filter;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.contrib.server.session.proxyprotocol.ProxyProtocolAcceptor;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.ProxyProtocolV2Acceptor;
import org.apache.sshd.server.session.ServerSession;

/**
 * A {@link IoFilter} that parses a proxy protocol header (either version 1 or 2) and sets the client address reported
 * on the {@link ServerSession}. Useful if a server is running behind a HAProxy.
 *
 * <p>
 * The filter is intended to be added in first place in a {@link ServerSession}'s filter chain.
 * </p>
 *
 * @see <a href="https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt">HAProxy Protocol 1 Documentation</a>
 * @see <a href="https://www.haproxy.org/download/2.7/doc/proxy-protocol.txt">HAProxy Protocol 2 Documentation</a>
 */
public class HAProxyProtocolFilter extends IoFilter {

    private AtomicReference<InputHandler> input = new AtomicReference<>();

    public HAProxyProtocolFilter(ServerSession session) {
        input.set(new ProxyHeaderReceiver(session));
    }

    @Override
    public InputHandler in() {
        return input.get();
    }

    @Override
    public OutputHandler out() {
        return null;
    }

    private class ProxyHeaderReceiver implements InputHandler {

        private final ServerSession session;

        private final ProxyProtocolAcceptor handler = new ProxyProtocolV2Acceptor();

        private Buffer buffer = new ByteArrayBuffer();

        ProxyHeaderReceiver(ServerSession session) {
            this.session = Objects.requireNonNull(session);
        }

        @Override
        public synchronized void received(Readable message) throws Exception {
            if (buffer == null) {
                owner().passOn(message);
            } else {
                buffer.putBuffer(message);
                if (handler.acceptServerProxyMetadata(session, buffer)) {
                    if (buffer.available() > 0) {
                        buffer.compact();
                        owner().passOn(buffer);
                    }
                    input.set(null);
                    buffer = null;
                }
            }
        }
    }
}
