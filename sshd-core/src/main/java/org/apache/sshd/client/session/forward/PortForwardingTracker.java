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

package org.apache.sshd.client.session.forward;

import java.nio.channels.Channel;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class PortForwardingTracker
        implements Channel, SessionHolder<ClientSession>, ClientSessionHolder {
    protected final AtomicBoolean open = new AtomicBoolean(true);
    private final ClientSession session;
    private final SshdSocketAddress localAddress;
    private final SshdSocketAddress boundAddress;

    protected PortForwardingTracker(
                                    ClientSession session, SshdSocketAddress localAddress, SshdSocketAddress boundAddress) {
        this.session = Objects.requireNonNull(session, "No client session provided");
        this.localAddress = Objects.requireNonNull(localAddress, "No local address specified");
        this.boundAddress = Objects.requireNonNull(boundAddress, "No bound address specified");
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    public SshdSocketAddress getLocalAddress() {
        return localAddress;
    }

    public SshdSocketAddress getBoundAddress() {
        return boundAddress;
    }

    @Override
    public ClientSession getClientSession() {
        return session;
    }

    @Override
    public ClientSession getSession() {
        return getClientSession();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[session=" + getClientSession()
               + ", localAddress=" + getLocalAddress()
               + ", boundAddress=" + getBoundAddress()
               + ", open=" + isOpen()
               + "]";
    }
}
