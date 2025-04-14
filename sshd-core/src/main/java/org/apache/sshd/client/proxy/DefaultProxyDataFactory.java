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
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

/**
 * A default implementation of a {@link ProxyDataFactory} based on the standard {@link java.net.ProxySelector}. Prefers
 * SOCKS proxies over HTTP proxies. If the {@link ProxySelector} returns multiple proxies of the same type, the first
 * one is chosen.
 */
public class DefaultProxyDataFactory implements ProxyDataFactory {

    private final ProxySelector selector;

    /**
     * Creates an instance that uses {@link ProxySelector#getDefault()}.
     */
    public DefaultProxyDataFactory() {
        this(ProxySelector.getDefault());
    }

    /**
     * Creates an instance that uses the given {@link ProxySelector}.
     *
     * @param selector {@link ProxySelector} to use; if {@code null}, no {@link ProxyData} will ever be returned.
     */
    public DefaultProxyDataFactory(ProxySelector selector) {
        this.selector = selector;
    }

    @Override
    public ProxyData get(InetSocketAddress remoteAddress) {
        if (selector == null) {
            return null;
        }
        try {
            List<Proxy> proxies = selector.select(new URI("socket://" + remoteAddress.getHostString()));
            ProxyData data = getData(proxies);
            if (data == null) {
                proxies = selector.select(new URI("https", "//" + remoteAddress.getHostString(), null));
                data = getData(proxies);
            }
            return data;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private ProxyData getData(List<Proxy> proxies) {
        if (proxies.isEmpty()) {
            return null;
        }
        Proxy proxy = proxies.get(0);
        SocketAddress address = proxy.address();
        if (!(address instanceof InetSocketAddress)) {
            return null;
        }
        return new ProxyData(proxy);
    }
}
