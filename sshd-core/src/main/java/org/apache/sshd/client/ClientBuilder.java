/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.client;

import java.util.Arrays;
import java.util.List;

import org.apache.sshd.client.kex.DHGClient;
import org.apache.sshd.client.kex.DHGEXClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.server.forward.TcpipServerChannel;

/**
 * SshClient builder
 */
public class ClientBuilder extends BaseBuilder<SshClient, ClientBuilder> {
    public static final Transformer<DHFactory,NamedFactory<KeyExchange>> DH2KEX =
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
    protected ServerKeyVerifier serverKeyVerifier;

    public ClientBuilder() {
        super();
    }

    public ClientBuilder serverKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = serverKeyVerifier;
        return me();
    }

    @Override
    protected ClientBuilder fillWithDefaultValues() {
        super.fillWithDefaultValues();
        if (keyExchangeFactories == null) {
            keyExchangeFactories = setUpDefaultKeyExchanges(false);
        }
        if (channelFactories == null) {
            channelFactories = Arrays.<NamedFactory<Channel>>asList(
                    TcpipServerChannel.ForwardedTcpipFactory.INSTANCE);
        }
        if (serverKeyVerifier == null) {
            serverKeyVerifier = AcceptAllServerKeyVerifier.INSTANCE;
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
        return client;
    }

    /**
     * @param ignoreUnsupported If {@code true} then all the default
     * key exchanges are included, regardless of whether they are currently
     * supported by the JCE. Otherwise, only the supported ones out of the
     * list are included
     * @return A {@link List} of the default {@link NamedFactory}
     * instances of the {@link KeyExchange}s according to the preference
     * order defined by {@link #DEFAULT_KEX_PREFERENCE}.
     * <B>Note:</B> the list may be filtered to exclude unsupported JCE
     * key exchanges according to the <tt>ignoreUnsupported</tt> parameter
     * @see BuiltinDHFactories#isSupported()
     */
    public static List<NamedFactory<KeyExchange>> setUpDefaultKeyExchanges(boolean ignoreUnsupported) {
        return NamedFactory.Utils.setUpTransformedFactories(ignoreUnsupported, DEFAULT_KEX_PREFERENCE, DH2KEX);
    }

    public static ClientBuilder builder() {
        return new ClientBuilder();
    }
}