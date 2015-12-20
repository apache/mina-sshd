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

package org.apache.sshd.client;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.global.OpenSshHostKeysHandler;
import org.apache.sshd.client.kex.DHGClient;
import org.apache.sshd.client.kex.DHGEXClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.server.forward.ForwardedTcpipFactory;

/**
 * SshClient builder
 */
public class ClientBuilder extends BaseBuilder<SshClient, ClientBuilder> {
    public static final Transformer<DHFactory, NamedFactory<KeyExchange>> DH2KEX =
        new Transformer<DHFactory, NamedFactory<KeyExchange>>() {
            @Override
            public NamedFactory<KeyExchange> transform(DHFactory factory) {
                if (factory == null) {
                    return null;
                } else if (factory.isGroupExchange()) {
                    return DHGEXClient.newFactory(factory);
                } else {
                    return DHGClient.newFactory(factory);
                }
            }
        };

    public static final List<NamedFactory<Channel>> DEFAULT_CHANNEL_FACTORIES =
            Collections.unmodifiableList(Arrays.<NamedFactory<Channel>>asList(ForwardedTcpipFactory.INSTANCE));
    public static final List<RequestHandler<ConnectionService>> DEFAULT_GLOBAL_REQUEST_HANDLERS =
            Collections.unmodifiableList(Arrays.<RequestHandler<ConnectionService>>asList(
                    OpenSshHostKeysHandler.INSTANCE));

    public static final ServerKeyVerifier DEFAULT_SERVER_KEY_VERIFIER = AcceptAllServerKeyVerifier.INSTANCE;
    public static final HostConfigEntryResolver DEFAULT_HOST_CONFIG_ENTRY_RESOLVER = DefaultConfigFileHostEntryResolver.INSTANCE;
    public static final ClientIdentityLoader DEFAULT_CLIENT_IDENTITY_LOADER = ClientIdentityLoader.DEFAULT;
    public static final FilePasswordProvider DEFAULT_FILE_PASSWORD_PROVIDER = FilePasswordProvider.EMPTY;

    protected ServerKeyVerifier serverKeyVerifier;
    protected Collection<String> serverKeyAlgorithmsFilter;
    protected HostConfigEntryResolver hostConfigEntryResolver;
    protected ClientIdentityLoader clientIdentityLoader;
    protected FilePasswordProvider filePasswordProvider;

    public ClientBuilder() {
        super();
    }

    public ClientBuilder serverKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = serverKeyVerifier;
        return me();
    }

    public ClientBuilder serverKeyAlgorithmsFilter(Collection<String> serverKeyAlgorithmsFilter) {
        this.serverKeyAlgorithmsFilter = serverKeyAlgorithmsFilter;
        return me();
    }

    public ClientBuilder hostConfigEntryResolver(HostConfigEntryResolver resolver) {
        this.hostConfigEntryResolver = resolver;
        return me();
    }

    public ClientBuilder clientIdentityLoader(ClientIdentityLoader loader) {
        this.clientIdentityLoader = loader;
        return me();
    }

    public ClientBuilder filePasswordProvider(FilePasswordProvider provider) {
        this.filePasswordProvider = provider;
        return me();
    }

    @Override
    protected ClientBuilder fillWithDefaultValues() {
        super.fillWithDefaultValues();

        if (keyExchangeFactories == null) {
            keyExchangeFactories = setUpDefaultKeyExchanges(false);
        }

        if (channelFactories == null) {
            channelFactories = DEFAULT_CHANNEL_FACTORIES;
        }

        if (globalRequestHandlers == null) {
            globalRequestHandlers = DEFAULT_GLOBAL_REQUEST_HANDLERS;
        }

        if (serverKeyVerifier == null) {
            serverKeyVerifier = DEFAULT_SERVER_KEY_VERIFIER;
        }

        if (hostConfigEntryResolver == null) {
            hostConfigEntryResolver = DEFAULT_HOST_CONFIG_ENTRY_RESOLVER;
        }

        if (clientIdentityLoader == null) {
            clientIdentityLoader = DEFAULT_CLIENT_IDENTITY_LOADER;
        }

        if (filePasswordProvider == null) {
            filePasswordProvider = DEFAULT_FILE_PASSWORD_PROVIDER;
        }

        if (factory == null) {
            factory = SshClient.DEFAULT_SSH_CLIENT_FACTORY;
        }

        return me();
    }

    @Override
    public SshClient build(boolean isFillWithDefaultValues) {
        SshClient client = super.build(isFillWithDefaultValues);
        client.setServerKeyVerifier(serverKeyVerifier);
        client.setServerKeyAlgorithmsFilter(serverKeyAlgorithmsFilter);
        client.setHostConfigEntryResolver(hostConfigEntryResolver);
        client.setClientIdentityLoader(clientIdentityLoader);
        client.setFilePasswordProvider(filePasswordProvider);
        return client;
    }

    /**
     * @param ignoreUnsupported If {@code true} then all the default
     *                          key exchanges are included, regardless of whether they are currently
     *                          supported by the JCE. Otherwise, only the supported ones out of the
     *                          list are included
     * @return A {@link List} of the default {@link NamedFactory}
     * instances of the {@link KeyExchange}s according to the preference
     * order defined by {@link #DEFAULT_KEX_PREFERENCE}.
     * <B>Note:</B> the list may be filtered to exclude unsupported JCE
     * key exchanges according to the <tt>ignoreUnsupported</tt> parameter
     * @see org.apache.sshd.common.kex.BuiltinDHFactories#isSupported()
     */
    public static List<NamedFactory<KeyExchange>> setUpDefaultKeyExchanges(boolean ignoreUnsupported) {
        return NamedFactory.Utils.setUpTransformedFactories(ignoreUnsupported, DEFAULT_KEX_PREFERENCE, DH2KEX);
    }

    public static ClientBuilder builder() {
        return new ClientBuilder();
    }
}