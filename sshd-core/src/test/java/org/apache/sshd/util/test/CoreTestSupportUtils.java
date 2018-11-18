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

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.shell.UnknownCommandFactory;

public final class CoreTestSupportUtils {
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
        SshClient client = SshClient.setUpDefaultClient();
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
        client.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
        return client;
    }

    public static SshServer setupTestServer(Class<?> anchor) {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(CommonTestSupportUtils.createTestHostKeyProvider(anchor));
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.setShellFactory(EchoShellFactory.INSTANCE);
        sshd.setCommandFactory(UnknownCommandFactory.INSTANCE);
        return sshd;
    }
}
