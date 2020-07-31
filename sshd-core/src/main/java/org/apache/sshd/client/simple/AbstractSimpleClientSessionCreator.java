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

package org.apache.sshd.client.simple;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.Channel;
import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSimpleClientSessionCreator extends AbstractSimpleClient implements ClientSessionCreator {
    private long connectTimeout;
    private long authenticateTimeout;

    protected AbstractSimpleClientSessionCreator() {
        this(DEFAULT_CONNECT_TIMEOUT, DEFAULT_AUTHENTICATION_TIMEOUT);
    }

    protected AbstractSimpleClientSessionCreator(long connTimeout, long authTimeout) {
        setConnectTimeout(connTimeout);
        setAuthenticationTimeout(authTimeout);
    }

    @Override
    public long getConnectTimeout() {
        return connectTimeout;
    }

    @Override
    public void setConnectTimeout(long timeout) {
        ValidateUtils.checkTrue(timeout > 0, "Non-positive connect timeout: %d", timeout);
        connectTimeout = timeout;
    }

    @Override
    public long getAuthenticationTimeout() {
        return authenticateTimeout;
    }

    @Override
    public void setAuthenticationTimeout(long timeout) {
        ValidateUtils.checkTrue(timeout > 0, "Non-positive authentication timeout: %d", timeout);
        authenticateTimeout = timeout;
    }

    @Override
    public ClientSession sessionLogin(SocketAddress target, String username, String password) throws IOException {
        return loginSession(connect(username, target), password);
    }

    @Override
    public ClientSession sessionLogin(SocketAddress target, String username, KeyPair identity) throws IOException {
        return loginSession(connect(username, target), identity);
    }

    @Override
    public ClientSession sessionLogin(String uri, String password) throws IOException {
        return loginSession(connect(uri), password);
    }

    @Override
    public ClientSession sessionLogin(String uri, KeyPair identity) throws IOException {
        return loginSession(connect(uri), identity);
    }

    protected ClientSession loginSession(ConnectFuture future, String password) throws IOException {
        return authSession(future.verify(getConnectTimeout()), password);
    }

    protected ClientSession loginSession(ConnectFuture future, KeyPair identity) throws IOException {
        return authSession(future.verify(getConnectTimeout()), identity);
    }

    protected ClientSession authSession(ConnectFuture future, String password) throws IOException {
        ClientSession session = future.getSession();
        session.addPasswordIdentity(password);
        return authSession(session);
    }

    protected ClientSession authSession(ConnectFuture future, KeyPair identity) throws IOException {
        ClientSession session = future.getSession();
        session.addPublicKeyIdentity(identity);
        return authSession(session);
    }

    protected ClientSession authSession(ClientSession clientSession) throws IOException {
        ClientSession session = clientSession;
        IOException err = null;
        try {
            AuthFuture auth = session.auth();
            auth.verify(getAuthenticationTimeout());
            session = null; // disable auto-close
        } catch (IOException e) {
            err = GenericUtils.accumulateException(err, e);
        } finally {
            if (session != null) {
                try {
                    session.close();
                } catch (IOException e) {
                    err = GenericUtils.accumulateException(err, e);
                }
            }
        }

        if (err != null) {
            throw err;
        }

        return clientSession;
    }

    /**
     * Wraps an existing {@link ClientSessionCreator} into a {@link SimpleClient}
     *
     * @param  creator The {@link ClientSessionCreator} - never {@code null}
     * @param  channel The {@link Channel} representing the creator for relaying {@link #isOpen()} and {@link #close()}
     *                 calls
     * @return         The {@link SimpleClient} wrapper. <B>Note:</B> closing the wrapper also closes the underlying
     *                 sessions creator.
     */
    @SuppressWarnings("checkstyle:anoninnerlength")
    public static SimpleClient wrap(ClientSessionCreator creator, Channel channel) {
        Objects.requireNonNull(creator, "No sessions creator");
        Objects.requireNonNull(channel, "No channel");
        return new AbstractSimpleClientSessionCreator() {
            @Override
            public ConnectFuture connect(String uri) throws IOException {
                return creator.connect(uri);
            }

            @Override
            public ConnectFuture connect(String username, String host, int port) throws IOException {
                return creator.connect(username, host, port);
            }

            @Override
            public ConnectFuture connect(String username, String host, int port, SocketAddress localAddress)
                    throws IOException {
                return creator.connect(username, host, port, localAddress);
            }

            @Override
            public ConnectFuture connect(String username, SocketAddress address) throws IOException {
                return creator.connect(username, address);
            }

            @Override
            public ConnectFuture connect(String username, SocketAddress targetAddress, SocketAddress localAddress)
                    throws IOException {
                return creator.connect(username, targetAddress, localAddress);
            }

            @Override
            public ConnectFuture connect(HostConfigEntry hostConfig) throws IOException {
                return creator.connect(hostConfig);
            }

            @Override
            public ConnectFuture connect(HostConfigEntry hostConfig, SocketAddress localAddress) throws IOException {
                return creator.connect(hostConfig, localAddress);
            }

            @Override
            public ConnectFuture connect(
                    HostConfigEntry hostConfig, AttributeRepository context, SocketAddress localAddress)
                    throws IOException {
                return creator.connect(hostConfig, context, localAddress);
            }

            @Override
            public ConnectFuture connect(
                    String username, SocketAddress targetAddress, AttributeRepository context, SocketAddress localAddress)
                    throws IOException {
                return creator.connect(username, targetAddress, context, localAddress);
            }

            @Override
            public ConnectFuture connect(
                    String username, String host, int port, AttributeRepository context, SocketAddress localAddress)
                    throws IOException {
                return creator.connect(username, host, port, context, localAddress);
            }

            @Override
            public ConnectFuture connect(HostConfigEntry hostConfig, AttributeRepository context) throws IOException {
                return creator.connect(hostConfig, context);
            }

            @Override
            public ConnectFuture connect(String username, SocketAddress address, AttributeRepository context)
                    throws IOException {
                return creator.connect(username, address, context);
            }

            @Override
            public ConnectFuture connect(String username, String host, int port, AttributeRepository context)
                    throws IOException {
                return creator.connect(username, host, port, context);
            }

            @Override
            public boolean isOpen() {
                return channel.isOpen();
            }

            @Override
            public void close() throws IOException {
                channel.close();
            }

            @Override
            public String toString() {
                return SimpleClient.class.getSimpleName() + "[" + channel + "]";
            }
        };
    }
}
