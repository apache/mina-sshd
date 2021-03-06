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
package org.apache.sshd.util.test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.shell.UnknownCommandFactory;

public final class CoreTestSupportUtils {
    public static final Duration READ_TIMEOUT = getTimeout("read.nio2", Duration.ofSeconds(60));

    private CoreTestSupportUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static int getFreePort() throws Exception {
        try (ServerSocket s = new ServerSocket()) {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress((InetAddress) null, 0));
            return s.getLocalPort();
        }
    }

    public static SshClient setupTestClient(Class<?> anchor) {
        return setupTestClient(SshClient.setUpDefaultClient(), anchor);
    }

    public static <C extends SshClient> C setupTestClient(C client, Class<?> anchor) {
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
        client.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
        CoreModuleProperties.NIO2_READ_TIMEOUT.set(client, READ_TIMEOUT);
        return client;
    }

    public static SshClient setupTestFullSupportClient(Class<?> anchor) {
        SshClient client = setupTestClient(anchor);
        return setupTestFullSupportClient(client);
    }

    public static SshClient setupTestFullSupportClient(SshClient client) {
        client.setKeyExchangeFactories(
                NamedFactory.setUpTransformedFactories(false, BuiltinDHFactories.VALUES, ClientBuilder.DH2KEX));
        setupFullSignaturesSupport(client);
        return client;
    }

    public static SshServer setupTestServer(Class<?> anchor) {
        return setupTestServer(SshServer.setUpDefaultServer(), anchor);
    }

    public static <S extends SshServer> S setupTestServer(S sshd, Class<?> anchor) {
        sshd.setKeyPairProvider(CommonTestSupportUtils.createTestHostKeyProvider(anchor));
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.setShellFactory(EchoShellFactory.INSTANCE);
        sshd.setCommandFactory(UnknownCommandFactory.INSTANCE);
        CoreModuleProperties.NIO2_READ_TIMEOUT.set(sshd, READ_TIMEOUT);
        return sshd;
    }

    // Adds deprecated / insecure settings
    public static SshServer setupTestFullSupportServer(Class<?> anchor) {
        SshServer sshd = setupTestServer(anchor);
        return setupTestFullSupportServer(sshd);
    }

    public static SshServer setupTestFullSupportServer(SshServer sshd) {
        sshd.setKeyExchangeFactories(
                NamedFactory.setUpTransformedFactories(false, BuiltinDHFactories.VALUES, ServerBuilder.DH2KEX));
        setupFullSignaturesSupport(sshd);
        return sshd;
    }

    public static <M extends AbstractFactoryManager> M setupFullSignaturesSupport(M manager) {
        manager.setSignatureFactories(new ArrayList<>(BuiltinSignatures.VALUES));
        return manager;
    }

    public static Duration getTimeout(String property, Duration defaultValue) {
        // Do we have a specific timeout value ?
        String str = System.getProperty("org.apache.sshd.test.timeout." + property);
        if (GenericUtils.isNotEmpty(str)) {
            return Duration.ofMillis(Long.parseLong(str));
        }

        // Do we have a specific factor ?
        str = System.getProperty("org.apache.sshd.test.timeout.factor." + property);
        if (GenericUtils.isEmpty(str)) {
            // Do we have a global factor ?
            str = System.getProperty("org.apache.sshd.test.timeout.factor");
        }

        if (GenericUtils.isNotEmpty(str)) {
            double factor = Double.parseDouble(str);
            long dur = Math.round(defaultValue.toMillis() * factor);
            return Duration.ofMillis(dur);
        }

        return defaultValue;
    }
}
