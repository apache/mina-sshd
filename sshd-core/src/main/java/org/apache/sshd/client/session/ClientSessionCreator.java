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

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientSessionCreator {
    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param username The intended username
     * @param host The target host name/address - never {@code null}/empty
     * @param port The target port
     * @return A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or
     * connect to it
     * @see #connect(HostConfigEntry)
     */
    ConnectFuture connect(String username, String host, int port) throws IOException;

    /**
     * Resolves the <U>effective</U> {@link HostConfigEntry} and connects to it
     *
     * @param username The intended username
     * @param address The intended {@link SocketAddress} - never {@code null}. If
     * this is an {@link java.net.InetSocketAddress} then the <U>effective</U> {@link HostConfigEntry}
     * is resolved and used.
     * @return A {@link ConnectFuture}
     * @throws IOException If failed to resolve the effective target or
     * connect to it
     * @see #connect(HostConfigEntry)
     */
    ConnectFuture connect(String username, SocketAddress address) throws IOException;

    /**
     * @param hostConfig The effective {@link HostConfigEntry} to connect to - never {@code null}
     * @return A {@link ConnectFuture}
     * @throws IOException If failed to create the connection future
     */
    ConnectFuture connect(HostConfigEntry hostConfig) throws IOException;
}
