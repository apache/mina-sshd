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
package org.apache.sshd.client.proxy;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;

/**
 * An object encapsulating the data needed to connect through a proxy server.
 */
public class ProxyData {

    private final Proxy proxy;

    private final String proxyUser;

    private final char[] proxyPassword;

    /**
     * Creates a new {@link ProxyData} instance without user name or password.
     *
     * @param proxy to connect to; must not be {@link java.net.Proxy.Type#DIRECT} and must have an
     *              {@link InetSocketAddress}.
     */
    public ProxyData(Proxy proxy) {
        this(proxy, null, null);
    }

    /**
     * Creates a new {@link ProxyData} instance.
     *
     * @param proxy         to connect to; must not be {@link java.net.Proxy.Type#DIRECT} and must have an
     *                      {@link InetSocketAddress}.
     * @param proxyUser     to use for log-in to the proxy, may be {@code null}
     * @param proxyPassword to use for log-in to the proxy, may be {@code null}
     */
    public ProxyData(Proxy proxy, String proxyUser, char[] proxyPassword) {
        if (!(proxy.address() instanceof InetSocketAddress)) {
            throw new IllegalArgumentException("Proxy does not have an InetSocketAddress");
        }
        this.proxy = proxy;
        this.proxyUser = proxyUser;
        this.proxyPassword = proxyPassword == null ? null : proxyPassword.clone();
    }

    /**
     * Obtains the {@link InetSocketAddress} to connect to.
     *
     * @return the {@link InetSocketAddress}
     */
    public InetSocketAddress getAddress() {
        return (InetSocketAddress) proxy.address();
    }

    /**
     * Obtains the {@link Proxy} to connect to.
     *
     * @return the {@link Proxy}, never {@code null}
     */
    public Proxy.Type getType() {
        return proxy.type();
    }

    /**
     * Obtains the user to log in at the proxy with.
     *
     * @return the user name, or {@code null} if none
     */
    public String getUser() {
        return proxyUser;
    }

    /**
     * Obtains a copy of the internally stored password.
     *
     * @return the password or {@code null} if none
     */
    public char[] getPassword() {
        return proxyPassword == null ? null : proxyPassword.clone();
    }

    /**
     * Clears the stored password, if any.
     */
    public void clearPassword() {
        if (proxyPassword != null) {
            Arrays.fill(proxyPassword, '\000');
        }
    }
}
