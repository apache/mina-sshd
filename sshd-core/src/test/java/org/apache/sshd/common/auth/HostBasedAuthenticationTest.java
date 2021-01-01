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

package org.apache.sshd.common.auth;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.hostbased.HostBasedAuthenticationReporter;
import org.apache.sshd.client.auth.hostbased.HostKeyIdentityProvider;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HostBasedAuthenticationTest extends AuthenticationTestSupport {
    public HostBasedAuthenticationTest() {
        super();
    }

    @Test // see SSHD-620
    public void testHostBasedAuthentication() throws Exception {
        AtomicInteger invocationCount = new AtomicInteger(0);
        testHostBasedAuthentication(
                (
                        session, username, clientHostKey, clientHostName, clientUsername,
                        certificates) -> invocationCount.incrementAndGet() > 0,
                session -> {
                    /* ignored */ });
        assertEquals("Mismatched authenticator invocation count", 1, invocationCount.get());
    }

    @Test   // see SSHD-1114
    public void testHostBasedAuthenticationReporter() throws Exception {
        AtomicReference<String> hostnameClientHolder = new AtomicReference<>();
        AtomicReference<String> usernameClientHolder = new AtomicReference<>();
        AtomicReference<PublicKey> keyClientHolder = new AtomicReference<>();
        HostBasedAuthenticator authenticator
                = (session, username, clientHostKey, clientHostName, clientUsername, certificates) -> {
                    return Objects.equals(clientHostName, hostnameClientHolder.get())
                            && Objects.equals(clientUsername, usernameClientHolder.get())
                            && KeyUtils.compareKeys(clientHostKey, keyClientHolder.get());
                };

        HostBasedAuthenticationReporter reporter = new HostBasedAuthenticationReporter() {
            @Override
            public void signalAuthenticationAttempt(
                    ClientSession session, String service, KeyPair identity, String hostname, String username, byte[] signature)
                    throws Exception {
                hostnameClientHolder.set(hostname);
                usernameClientHolder.set(username);
                keyClientHolder.set(identity.getPublic());
            }

            @Override
            public void signalAuthenticationSuccess(
                    ClientSession session, String service, KeyPair identity, String hostname, String username)
                    throws Exception {
                assertEquals("Host", hostname, hostnameClientHolder.get());
                assertEquals("User", username, usernameClientHolder.get());
                assertKeyEquals("Identity", identity.getPublic(), keyClientHolder.get());
            }

            @Override
            public void signalAuthenticationFailure(
                    ClientSession session, String service, KeyPair identity,
                    String hostname, String username, boolean partial, List<String> serverMethods)
                    throws Exception {
                fail("Unexpected failure signalled");
            }
        };

        testHostBasedAuthentication(authenticator, session -> session.setHostBasedAuthenticationReporter(reporter));
    }

    private void testHostBasedAuthentication(
            HostBasedAuthenticator delegate, Consumer<? super ClientSession> preAuthInitializer)
            throws Exception {
        String hostClientUser = getClass().getSimpleName();
        String hostClientName = SshdSocketAddress.toAddressString(SshdSocketAddress.getFirstExternalNetwork4Address());
        KeyPair hostClientKey = CommonTestSupportUtils.generateKeyPair(
                CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM,
                CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_SIZE);
        sshd.setHostBasedAuthenticator((session, username, clientHostKey, clientHostName, clientUsername, certificates) -> {
            return hostClientUser.equals(clientUsername)
                    && hostClientName.equals(clientHostName)
                    && KeyUtils.compareKeys(hostClientKey.getPublic(), clientHostKey)
                    && delegate.authenticate(session, username, clientHostKey, clientHostName, clientUsername, certificates);
        });
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        sshd.setUserAuthFactories(
                Collections.singletonList(
                        org.apache.sshd.server.auth.hostbased.UserAuthHostBasedFactory.INSTANCE));

        try (SshClient client = setupTestClient()) {
            org.apache.sshd.client.auth.hostbased.UserAuthHostBasedFactory factory
                    = new org.apache.sshd.client.auth.hostbased.UserAuthHostBasedFactory();
            // TODO factory.setClientHostname(CLIENT_HOSTNAME);
            factory.setClientUsername(hostClientUser);
            factory.setClientHostKeys(HostKeyIdentityProvider.wrap(hostClientKey));

            client.setUserAuthFactories(Collections.singletonList(factory));
            client.start();
            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                preAuthInitializer.accept(session);
                session.auth().verify(AUTH_TIMEOUT);
            } finally {
                client.stop();
            }
        }
    }
}
