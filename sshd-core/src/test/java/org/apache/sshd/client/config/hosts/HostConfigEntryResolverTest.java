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

package org.apache.sshd.client.config.hosts;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HostConfigEntryResolverTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;

    public HostConfigEntryResolverTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.start();
        port = sshd.getPort();

        client = setupTestClient();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    public void testEffectiveHostConfigResolution() throws Exception {
        HostConfigEntry entry = new HostConfigEntry(getCurrentTestName(), TEST_LOCALHOST, port, getCurrentTestName());
        client.setHostConfigEntryResolver((host, portValue, lclAddress, username, proxy, context) -> entry);
        client.start();

        try (ClientSession session = client.connect(
                getClass().getSimpleName(),
                getClass().getPackage().getName(),
                getMovedPortNumber(port)).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            assertEffectiveRemoteAddress(session, entry);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testNegatedHostEntriesResolution() throws Exception {
        HostConfigEntry positiveEntry = new HostConfigEntry(TEST_LOCALHOST, TEST_LOCALHOST, port, getCurrentTestName());
        HostConfigEntry negativeEntry = new HostConfigEntry(
                Character.toString(HostPatternsHolder.NEGATION_CHAR_PATTERN) + positiveEntry.getHost(),
                positiveEntry.getHostName(),
                getMovedPortNumber(positiveEntry.getPort()),
                getClass().getPackage().getName());
        client.setHostConfigEntryResolver(
                HostConfigEntry.toHostConfigEntryResolver(
                        Arrays.asList(negativeEntry, positiveEntry)));
        client.start();

        try (ClientSession session = client.connect(
                negativeEntry.getUsername(),
                negativeEntry.getHostName(),
                negativeEntry.getPort()).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            assertEffectiveRemoteAddress(session, positiveEntry);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPreloadedIdentities() throws Exception {
        KeyPair identity = CommonTestSupportUtils.getFirstKeyPair(sshd);
        String user = getCurrentTestName();
        // make sure authentication is achieved only via the identity public key
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            if (user.equals(username)) {
                return KeyUtils.compareKeys(identity.getPublic(), key);
            }

            return false;
        });
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);

        String clientIdentity = getCurrentTestName();
        client.setClientIdentityLoader(new ClientIdentityLoader() {
            @Override
            public boolean isValidLocation(NamedResource location) throws IOException {
                return Objects.equals(clientIdentity, location.getName());
            }

            @Override
            public Iterable<KeyPair> loadClientIdentities(
                    SessionContext session, NamedResource location, FilePasswordProvider provider)
                    throws IOException, GeneralSecurityException {
                if (isValidLocation(location)) {
                    return Collections.singletonList(identity);
                }

                throw new FileNotFoundException("Unknown location: " + location);
            }
        });
        CoreModuleProperties.IGNORE_INVALID_IDENTITIES.set(client, false);

        String host = getClass().getSimpleName();
        HostConfigEntry entry = new HostConfigEntry(host, TEST_LOCALHOST, port, user);
        entry.addIdentity(clientIdentity);
        client.setHostConfigEntryResolver((host1, portValue, lclAddress, username, proxy, context) -> entry);

        client.start();
        try (ClientSession session = client.connect(
                user, host, getMovedPortNumber(port)).verify(CONNECT_TIMEOUT).getSession()) {
            session.auth().verify(AUTH_TIMEOUT);
            assertEffectiveRemoteAddress(session, entry);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testUseIdentitiesOnly() throws Exception {
        Path clientIdFile = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        KeyIdentityProvider clientIdProvider
                = CommonTestSupportUtils.createTestHostKeyProvider(clientIdFile.resolve(getCurrentTestName() + ".pem"));
        KeyPair specificIdentity = CommonTestSupportUtils.getFirstKeyPair(sshd);
        KeyPair defaultIdentity = CommonTestSupportUtils.getFirstKeyPair(clientIdProvider);
        ValidateUtils.checkTrue(!KeyUtils.compareKeyPairs(specificIdentity, defaultIdentity),
                "client identity not different then entry one");
        client.setKeyIdentityProvider(clientIdProvider);

        String user = getCurrentTestName();
        AtomicBoolean defaultClientIdentityAttempted = new AtomicBoolean(false);
        // make sure authentication is achieved only via the identity public key
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            if (KeyUtils.compareKeys(defaultIdentity.getPublic(), key)) {
                defaultClientIdentityAttempted.set(true);
            }

            if (user.equals(username)) {
                return KeyUtils.compareKeys(specificIdentity.getPublic(), key);
            }

            return false;
        });
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);

        String clientIdentity = getCurrentTestName();
        HostConfigEntry entry = new HostConfigEntry(TEST_LOCALHOST, TEST_LOCALHOST, port, user);
        entry.addIdentity(clientIdentity);
        entry.setIdentitiesOnly(true);

        AtomicInteger specificIdentityLoadCount = new AtomicInteger(0);
        client.setClientIdentityLoader(new ClientIdentityLoader() {
            @Override
            public boolean isValidLocation(NamedResource location) throws IOException {
                return Objects.equals(clientIdentity, location.getName());
            }

            @Override
            public Iterable<KeyPair> loadClientIdentities(
                    SessionContext session, NamedResource location, FilePasswordProvider provider)
                    throws IOException, GeneralSecurityException {
                if (isValidLocation(location)) {
                    specificIdentityLoadCount.incrementAndGet();
                    return Collections.singletonList(specificIdentity);
                }

                throw new FileNotFoundException("Unknown location: " + location);
            }
        });
        CoreModuleProperties.IGNORE_INVALID_IDENTITIES.set(client, false);

        Collection<KeyPair> clientIdentities = Collections.singletonList(defaultIdentity);
        KeyIdentityProvider provider = new AbstractKeyPairProvider() {
            @Override
            public Iterable<KeyPair> loadKeys(SessionContext session) {
                return clientIdentities;
            }
        };
        client.setKeyIdentityProvider(provider);

        client.start();
        try (ClientSession session = client.connect(entry)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.auth().verify(AUTH_TIMEOUT);
            assertFalse("Unexpected default client identity attempted", defaultClientIdentityAttempted.get());
            assertNull("Default client identity auto-added", session.removePublicKeyIdentity(defaultIdentity));
            assertEquals("Entry identity not used", 1, specificIdentityLoadCount.get());
            assertEffectiveRemoteAddress(session, entry);
        } finally {
            client.stop();
        }
    }

    private static int getMovedPortNumber(int port) {
        return (port > Short.MAX_VALUE) ? (port - Short.MAX_VALUE) : (1 + Short.MAX_VALUE - port);
    }

    private static <S extends Session> S assertEffectiveRemoteAddress(S session, HostConfigEntry entry) {
        IoSession ioSession = session.getIoSession();
        SocketAddress remoteAddress = ioSession.getRemoteAddress();
        InetSocketAddress inetAddress = SshdSocketAddress.toInetSocketAddress(remoteAddress);
        assertEquals("Mismatched effective port", entry.getPort(), inetAddress.getPort());
        assertEquals("Mismatched effective user", entry.getUsername(), session.getUsername());
        return session;
    }
}
