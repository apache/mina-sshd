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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.net.SocketAddress;

import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientSessionCreator {

    AttributeRepository.AttributeKey<SshdSocketAddress> TARGET_SERVER = new AttributeRepository.AttributeKey<>();

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  uri         The server uri to connect to
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or connect to it
     * @see                #connect(HostConfigEntry)
     */
    ConnectFuture connect(String uri) throws IOException;

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username    The intended username
     * @param  host        The target host name/address - never {@code null}/empty
     * @param  port        The target port
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or connect to it
     * @see                #connect(HostConfigEntry)
     */
    default ConnectFuture connect(String username, String host, int port) throws IOException {
        return connect(username, host, port, (AttributeRepository) null);
    }

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username    The intended username
     * @param  host        The target host name/address - never {@code null}/empty
     * @param  port        The target port
     * @param  context     An optional &quot;context&quot; to be attached to the established session if successfully
     *                     connected
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or connect to it
     */
    default ConnectFuture connect(
            String username, String host, int port, AttributeRepository context)
            throws IOException {
        return connect(username, host, port, context, null);
    }

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username     The intended username
     * @param  host         The target host name/address - never {@code null}/empty
     * @param  port         The target port
     * @param  localAddress The local address to use - if {@code null} an automatic ephemeral port and bind address is
     *                      used
     * @return              A {@link ConnectFuture}
     * @throws IOException  If failed to resolve the effective target or connect to it
     * @see                 #connect(HostConfigEntry)
     */
    default ConnectFuture connect(
            String username, String host, int port, SocketAddress localAddress)
            throws IOException {
        return connect(username, host, port, null, localAddress);
    }

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username     The intended username
     * @param  host         The target host name/address - never {@code null}/empty
     * @param  port         The target port
     * @param  context      An optional &quot;context&quot; to be attached to the established session if successfully
     *                      connected
     * @param  localAddress The local address to use - if {@code null} an automatic ephemeral port and bind address is
     *                      used
     * @return              A {@link ConnectFuture}
     * @throws IOException  If failed to resolve the effective target or connect to it
     */
    ConnectFuture connect(
            String username, String host, int port, AttributeRepository context, SocketAddress localAddress)
            throws IOException;

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username    The intended username
     * @param  address     The intended {@link SocketAddress} - never {@code null}. If this is an
     *                     {@link java.net.InetSocketAddress} then the <U>effective</U> {@link HostConfigEntry} is
     *                     resolved and used.
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or connect to it
     * @see                #connect(HostConfigEntry)
     */
    default ConnectFuture connect(String username, SocketAddress address) throws IOException {
        return connect(username, address, (AttributeRepository) null);
    }

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username    The intended username
     * @param  address     The intended {@link SocketAddress} - never {@code null}. If this is an
     *                     {@link java.net.InetSocketAddress} then the <U>effective</U> {@link HostConfigEntry} is
     *                     resolved and used.
     * @param  context     An optional &quot;context&quot; to be attached to the established session if successfully
     *                     connected
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or connect to it
     */
    default ConnectFuture connect(
            String username, SocketAddress address, AttributeRepository context)
            throws IOException {
        return connect(username, address, context, null);
    }

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username      The intended username
     * @param  targetAddress The intended target {@link SocketAddress} - never {@code null}. If this is an
     *                       {@link java.net.InetSocketAddress} then the <U>effective</U> {@link HostConfigEntry} is
     *                       resolved and used.
     * @param  localAddress  The local address to use - if {@code null} an automatic ephemeral port and bind address is
     *                       used
     * @return               A {@link ConnectFuture}
     * @throws IOException   If failed to resolve the effective target or connect to it
     * @see                  #connect(HostConfigEntry)
     */
    default ConnectFuture connect(
            String username, SocketAddress targetAddress, SocketAddress localAddress)
            throws IOException {
        return connect(username, targetAddress, null, localAddress);
    }

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param  username      The intended username
     * @param  targetAddress The intended target {@link SocketAddress} - never {@code null}. If this is an
     *                       {@link java.net.InetSocketAddress} then the <U>effective</U> {@link HostConfigEntry} is
     *                       resolved and used.
     * @param  context       An optional &quot;context&quot; to be attached to the established session if successfully
     *                       connected
     * @param  localAddress  The local address to use - if {@code null} an automatic ephemeral port and bind address is
     *                       used
     * @return               A {@link ConnectFuture}
     * @throws IOException   If failed to resolve the effective target or connect to it
     */
    ConnectFuture connect(
            String username, SocketAddress targetAddress, AttributeRepository context, SocketAddress localAddress)
            throws IOException;

    /**
     * @param  hostConfig  The effective {@link HostConfigEntry} to connect to - never {@code null}
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to create the connection future
     */
    default ConnectFuture connect(HostConfigEntry hostConfig) throws IOException {
        return connect(hostConfig, (AttributeRepository) null);
    }

    /**
     * @param  hostConfig  The effective {@link HostConfigEntry} to connect to - never {@code null}
     * @param  context     An optional &quot;context&quot; to be attached to the established session if successfully
     *                     connected
     * @return             A {@link ConnectFuture}
     * @throws IOException If failed to create the connection future
     */
    default ConnectFuture connect(HostConfigEntry hostConfig, AttributeRepository context) throws IOException {
        return connect(hostConfig, context, null);
    }

    /**
     * @param  hostConfig   The effective {@link HostConfigEntry} to connect to - never {@code null}
     * @param  localAddress The local address to use - if {@code null} an automatic ephemeral port and bind address is
     *                      used
     * @return              A {@link ConnectFuture}
     * @throws IOException  If failed to create the connection future
     */
    default ConnectFuture connect(HostConfigEntry hostConfig, SocketAddress localAddress) throws IOException {
        return connect(hostConfig, null, localAddress);
    }

    /**
     * @param  hostConfig   The effective {@link HostConfigEntry} to connect to - never {@code null}
     * @param  context      An optional &quot;context&quot; to be attached to the established session if successfully
     *                      connected
     * @param  localAddress The local address to use - if {@code null} an automatic ephemeral port and bind address is
     *                      used
     * @return              A {@link ConnectFuture}
     * @throws IOException  If failed to create the connection future
     */
    ConnectFuture connect(
            HostConfigEntry hostConfig, AttributeRepository context, SocketAddress localAddress)
            throws IOException;
}
