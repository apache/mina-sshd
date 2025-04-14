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
package org.apache.sshd.client.session.proxy;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;

import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.functors.IOFunction;

/**
 * Basic common functionality for tunneling through to a proxy.
 */
public abstract class AbstractProxyConnector implements Closeable {

    /** The proxy address. */
    protected final InetSocketAddress proxyAddress;

    /** The ultimate remote address to connect to. */
    protected final InetSocketAddress remoteAddress;

    protected String proxyUser;

    protected char[] proxyPassword;

    protected boolean done;

    private final IOFunction<Buffer, IoWriteFuture> send;

    private final Function<InetSocketAddress, PasswordAuthentication> passwordAuth;

    /**
     * Creates a new {@link AbstractProxyConnector}.
     *
     * @param proxy         {@link ProxyData} of the proxy we're connected to
     * @param remoteAddress {@link InetSocketAddress} of the target server to connect to
     * @param send          a function to send data and returning an {@link IoWriteFuture}
     * @param passwordAuth  a function to query the user for proxy credentials, if needed, and returning a
     *                      {@link PasswordAuthentication}
     */
    protected AbstractProxyConnector(ProxyData proxy, InetSocketAddress remoteAddress,
                                     IOFunction<Buffer, IoWriteFuture> send,
                                     Function<InetSocketAddress, PasswordAuthentication> passwordAuth) {
        this.proxyAddress = proxy.getAddress();
        this.proxyUser = proxy.getUser();
        char[] pass = proxy.getPassword();
        this.proxyPassword = pass != null ? pass.clone() : new char[0];
        proxy.clearPassword();
        this.remoteAddress = Objects.requireNonNull(remoteAddress);
        this.send = send;
        this.passwordAuth = passwordAuth;
    }

    protected IoWriteFuture write(Buffer message) throws IOException {
        return send.apply(message);
    }

    protected PasswordAuthentication passwordAuthentication() {
        return passwordAuth.apply(proxyAddress);
    }

    protected void clearPassword() {
        Arrays.fill(proxyPassword, '\000');
        proxyPassword = new char[0];
    }

    public boolean isDone() {
        return done;
    }

    @Override
    public void close() {
        clearPassword();
    }

    /**
     * Processes incoming data, and returns a {@link Buffer} containing any extra data from {@code message} that was not
     * yet processed.
     *
     * @param  message   the received data
     * @throws Exception if an error occurs
     */
    public abstract Buffer received(Readable message) throws Exception;

    /**
     * Starts the proxy protocol by sending the initial connection request message to the proxy.
     *
     * @throws IOException if the message cannot be sent
     */
    public abstract void start() throws IOException;

}
