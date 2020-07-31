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

package org.apache.sshd.server;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.config.keys.DefaultAuthorizedKeysAuthenticator;
import org.apache.sshd.server.forward.DirectTcpipFactory;
import org.apache.sshd.server.global.CancelTcpipForwardHandler;
import org.apache.sshd.server.global.KeepAliveHandler;
import org.apache.sshd.server.global.NoMoreSessionsHandler;
import org.apache.sshd.server.global.OpenSshHostKeysHandler;
import org.apache.sshd.server.global.TcpipForwardHandler;
import org.apache.sshd.server.kex.DHGEXServer;
import org.apache.sshd.server.kex.DHGServer;

/**
 * SshServer builder
 */
public class ServerBuilder extends BaseBuilder<SshServer, ServerBuilder> {
    @SuppressWarnings("checkstyle:Indentation")
    public static final Function<DHFactory, KeyExchangeFactory> DH2KEX = factory -> factory == null
            ? null
            : factory.isGroupExchange()
                    ? DHGEXServer.newFactory(factory)
            : DHGServer.newFactory(factory);

    public static final List<ChannelFactory> DEFAULT_CHANNEL_FACTORIES = Collections.unmodifiableList(
            Arrays.asList(
                    ChannelSessionFactory.INSTANCE,
                    DirectTcpipFactory.INSTANCE));

    public static final List<RequestHandler<ConnectionService>> DEFAULT_GLOBAL_REQUEST_HANDLERS = Collections.unmodifiableList(
            Arrays.<RequestHandler<ConnectionService>> asList(
                    KeepAliveHandler.INSTANCE,
                    NoMoreSessionsHandler.INSTANCE,
                    TcpipForwardHandler.INSTANCE,
                    CancelTcpipForwardHandler.INSTANCE,
                    OpenSshHostKeysHandler.INSTANCE));

    public static final PublickeyAuthenticator DEFAULT_PUBLIC_KEY_AUTHENTICATOR = DefaultAuthorizedKeysAuthenticator.INSTANCE;
    public static final KeyboardInteractiveAuthenticator DEFAULT_INTERACTIVE_AUTHENTICATOR
            = DefaultKeyboardInteractiveAuthenticator.INSTANCE;
    public static final List<CompressionFactory> DEFAULT_COMPRESSION_FACTORIES = Collections.unmodifiableList(
            Arrays.<CompressionFactory> asList(
                    BuiltinCompressions.none,
                    BuiltinCompressions.zlib,
                    BuiltinCompressions.delayedZlib));

    protected PublickeyAuthenticator pubkeyAuthenticator;
    protected KeyboardInteractiveAuthenticator interactiveAuthenticator;

    public ServerBuilder() {
        super();
    }

    public ServerBuilder interactiveAuthenticator(KeyboardInteractiveAuthenticator auth) {
        interactiveAuthenticator = auth;
        return this;
    }

    public ServerBuilder publickeyAuthenticator(PublickeyAuthenticator auth) {
        pubkeyAuthenticator = auth;
        return this;
    }

    @Override
    protected ServerBuilder fillWithDefaultValues() {
        super.fillWithDefaultValues();

        if (compressionFactories == null) {
            compressionFactories = setUpDefaultCompressionFactories(false);
        }

        if (signatureFactories == null) {
            signatureFactories = setUpDefaultSignatureFactories(false);
        }

        if (keyExchangeFactories == null) {
            keyExchangeFactories = setUpDefaultKeyExchanges(false);
        }

        if (channelFactories == null) {
            channelFactories = DEFAULT_CHANNEL_FACTORIES;
        }

        if (globalRequestHandlers == null) {
            globalRequestHandlers = DEFAULT_GLOBAL_REQUEST_HANDLERS;
        }

        if (pubkeyAuthenticator == null) {
            pubkeyAuthenticator = DEFAULT_PUBLIC_KEY_AUTHENTICATOR;
        }

        if (interactiveAuthenticator == null) {
            interactiveAuthenticator = DEFAULT_INTERACTIVE_AUTHENTICATOR;
        }

        if (factory == null) {
            factory = SshServer.DEFAULT_SSH_SERVER_FACTORY;
        }

        return me();
    }

    @Override
    public SshServer build(boolean isFillWithDefaultValues) {
        SshServer server = super.build(isFillWithDefaultValues);
        server.setPublickeyAuthenticator(pubkeyAuthenticator);
        server.setKeyboardInteractiveAuthenticator(interactiveAuthenticator);
        return server;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" }) // safe due to the hierarchy
    public static List<NamedFactory<Signature>> setUpDefaultSignatureFactories(boolean ignoreUnsupported) {
        return (List) NamedFactory.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_SIGNATURE_PREFERENCE);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" }) // safe due to the hierarchy
    public static List<NamedFactory<Compression>> setUpDefaultCompressionFactories(boolean ignoreUnsupported) {
        return (List) NamedFactory.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_COMPRESSION_FACTORIES);
    }

    /**
     * @param  ignoreUnsupported If {@code true} then all the default key exchanges are included, regardless of whether
     *                           they are currently supported by the JCE. Otherwise, only the supported ones out of the
     *                           list are included
     * @return                   A {@link List} of the default {@link NamedFactory} instances of the
     *                           {@link KeyExchange}s according to the preference order defined by
     *                           {@link #DEFAULT_KEX_PREFERENCE}. <B>Note:</B> the list may be filtered to exclude
     *                           unsupported JCE key exchanges according to the <tt>ignoreUnsupported</tt> parameter
     * @see                      org.apache.sshd.common.kex.BuiltinDHFactories#isSupported()
     */
    public static List<KeyExchangeFactory> setUpDefaultKeyExchanges(boolean ignoreUnsupported) {
        return NamedFactory.setUpTransformedFactories(ignoreUnsupported, DEFAULT_KEX_PREFERENCE, DH2KEX);
    }

    public static ServerBuilder builder() {
        return new ServerBuilder();
    }
}
