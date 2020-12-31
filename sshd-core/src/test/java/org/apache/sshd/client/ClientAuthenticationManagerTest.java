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

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.BuiltinUserAuthFactories;
import org.apache.sshd.client.auth.UserAuthFactory;
import org.apache.sshd.client.auth.hostbased.HostBasedAuthenticationReporter;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.pubkey.PublicKeyAuthenticationReporter;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.forward.DefaultForwarderFactory;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientAuthenticationManagerTest extends BaseTestSupport {
    public ClientAuthenticationManagerTest() {
        super();
    }

    @Test
    public void testDefaultUserAuthFactoriesMethods() {
        AtomicReference<List<UserAuthFactory>> factoriesHolder = new AtomicReference<>();
        @SuppressWarnings("checkstyle:anoninnerlength")
        ClientAuthenticationManager manager = new ClientAuthenticationManager() {
            @Override
            public List<UserAuthFactory> getUserAuthFactories() {
                return factoriesHolder.get();
            }

            @Override
            public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
                assertNull("Unexpected multiple invocation", factoriesHolder.getAndSet(userAuthFactories));
            }

            @Override
            public KeyIdentityProvider getKeyIdentityProvider() {
                return null;
            }

            @Override
            public void setKeyIdentityProvider(KeyIdentityProvider provider) {
                throw new UnsupportedOperationException("setKeyIdentityProvider(" + provider + ")");
            }

            @Override
            public PublicKeyAuthenticationReporter getPublicKeyAuthenticationReporter() {
                return null;
            }

            @Override
            public void setPublicKeyAuthenticationReporter(PublicKeyAuthenticationReporter reporter) {
                throw new UnsupportedOperationException("setPublicKeyAuthenticationReporter(" + reporter + ")");
            }

            @Override
            public HostBasedAuthenticationReporter getHostBasedAuthenticationReporter() {
                return null;
            }

            @Override
            public void setHostBasedAuthenticationReporter(HostBasedAuthenticationReporter reporter) {
                throw new UnsupportedOperationException("setHostBasedAuthenticationReporter(" + reporter + ")");
            }

            @Override
            public UserInteraction getUserInteraction() {
                return null;
            }

            @Override
            public void setUserInteraction(UserInteraction userInteraction) {
                throw new UnsupportedOperationException("setUserInteraction(" + userInteraction + ")");
            }

            @Override
            public PasswordAuthenticationReporter getPasswordAuthenticationReporter() {
                return null;
            }

            @Override
            public void setPasswordAuthenticationReporter(PasswordAuthenticationReporter reporter) {
                throw new UnsupportedOperationException("setPasswordAuthenticationReporter(" + reporter + ")");
            }

            @Override
            public ServerKeyVerifier getServerKeyVerifier() {
                return null;
            }

            @Override
            public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
                throw new UnsupportedOperationException("setServerKeyVerifier(" + serverKeyVerifier + ")");
            }

            @Override
            public PasswordIdentityProvider getPasswordIdentityProvider() {
                return null;
            }

            @Override
            public void setPasswordIdentityProvider(PasswordIdentityProvider provider) {
                throw new UnsupportedOperationException("setPasswordIdentityProvider(" + provider + ")");
            }

            @Override
            public AuthenticationIdentitiesProvider getRegisteredIdentities() {
                return null;
            }

            @Override
            public void addPublicKeyIdentity(KeyPair key) {
                throw new UnsupportedOperationException("addPublicKeyIdentity(" + key + ")");
            }

            @Override
            public KeyPair removePublicKeyIdentity(KeyPair kp) {
                throw new UnsupportedOperationException("removePublicKeyIdentity(" + kp + ")");
            }

            @Override
            public void addPasswordIdentity(String password) {
                throw new UnsupportedOperationException("addPasswordIdentity(" + password + ")");
            }

            @Override
            public String removePasswordIdentity(String password) {
                throw new UnsupportedOperationException("removePasswordIdentity(" + password + ")");
            }
        };
        assertEquals("Mismatched initial factories list", "", manager.getUserAuthFactoriesNameList());

        String expected = NamedResource.getNames(BuiltinUserAuthFactories.VALUES);
        manager.setUserAuthFactoriesNameList(expected);
        assertEquals("Mismatched updated factories names", expected, manager.getUserAuthFactoriesNameList());

        List<UserAuthFactory> factories = factoriesHolder.get();
        assertEquals("Mismatched factories count",
                BuiltinUserAuthFactories.VALUES.size(), GenericUtils.size(factories));
        for (BuiltinUserAuthFactories f : BuiltinUserAuthFactories.VALUES) {
            assertTrue("Missing factory=" + f.name(), factories.contains(f.create()));
        }
    }

    @Test
    public void testAddRemoveClientSessionIdentities() throws Exception {
        try (ClientSession session = createMockClientSession()) {
            testClientAuthenticationManager(session);
        }
    }

    @Test
    public void testAddRemoveSshClientIdentities() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            testClientAuthenticationManager(client);
        }
    }

    @Test
    public void testClientProvidersPropagation() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServiceFactories(SshClient.DEFAULT_SERVICE_FACTORIES);
            client.setUserAuthFactories(SshClient.DEFAULT_USER_AUTH_FACTORIES);

            try (ClientSession session = createMockClientSession(client)) {
                for (Class<?> provider : new Class<?>[] {
                        PasswordIdentityProvider.class,
                        ServerKeyVerifier.class,
                        UserInteraction.class,
                        KeyIdentityProvider.class,
                        PasswordAuthenticationReporter.class
                }) {
                    testClientProvidersPropagation(provider, client, session);
                }
            }
        }
    }

    private void testClientProvidersPropagation(
            Class<?> type, ClientAuthenticationManager client, ClientAuthenticationManager session)
            throws Exception {
        String baseName = type.getSimpleName();
        outputDebugMessage("testClientProvidersPropagation(%s)", baseName);
        assertTrue(baseName + ": not an interface", type.isInterface());

        Method getter = ClientAuthenticationManager.class.getMethod("get" + baseName);
        Method setter = ClientAuthenticationManager.class.getMethod("set" + baseName, type);
        Object clientProvider = Mockito.mock(type);
        setter.invoke(client, clientProvider);
        assertSame(baseName + ": mismatched client-only provider", clientProvider, getter.invoke(session));

        Object sessionProvider = Mockito.mock(type);
        setter.invoke(session, sessionProvider);
        assertSame(baseName + ": mismatched session override provider", sessionProvider, getter.invoke(session));

        setter.invoke(session, new Object[] { null });
        assertSame(baseName + ": mismatched nullified session provider", clientProvider, getter.invoke(session));
    }

    private <M extends ClientAuthenticationManager> M testClientAuthenticationManager(M manager) {
        if (manager != null) {
            String expected = getCurrentTestName();
            assertNull("Unexpected initial password identity", manager.removePasswordIdentity(expected));
            manager.addPasswordIdentity(expected);

            String actual = manager.removePasswordIdentity(expected);
            assertSame("Mismatched removed password identity", expected, actual);
            assertNull("Password identity not removed", manager.removePasswordIdentity(expected));
        }

        if (manager != null) {
            KeyPair expected = new KeyPair(Mockito.mock(PublicKey.class), Mockito.mock(PrivateKey.class));
            assertNull("Unexpected initial pubket identity", manager.removePublicKeyIdentity(expected));
            manager.addPublicKeyIdentity(expected);

            KeyPair actual = manager.removePublicKeyIdentity(expected);
            assertSame("Mismatched removed pubkey identity", expected, actual);
            assertNull("Pubkey identity not removed", manager.removePublicKeyIdentity(expected));
        }

        return manager;
    }

    private ClientSession createMockClientSession() throws Exception {
        ClientFactoryManager client = Mockito.mock(ClientFactoryManager.class);
        Mockito.when(client.getForwarderFactory()).thenReturn(DefaultForwarderFactory.INSTANCE);
        Mockito.when(client.getSessionListenerProxy()).thenReturn(new SessionListener() {
            @Override
            public void sessionEvent(Session session, Event event) {
                // ignored
            }

            @Override
            public void sessionCreated(Session session) {
                // ignored
            }

            @Override
            public void sessionException(Session session, Throwable t) {
                // ignored
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        });
        Mockito.when(client.getChannelListenerProxy()).thenReturn(ChannelListener.EMPTY);
        Mockito.when(client.getPortForwardingEventListenerProxy()).thenReturn(PortForwardingEventListener.EMPTY);
        Factory<Random> randomFactory = new SingletonRandomFactory(JceRandomFactory.INSTANCE);
        Mockito.when(client.getRandomFactory()).thenReturn(randomFactory);

        Mockito.when(client.getServiceFactories()).thenReturn(SshClient.DEFAULT_SERVICE_FACTORIES);
        Mockito.when(client.getUserAuthFactories()).thenReturn(SshClient.DEFAULT_USER_AUTH_FACTORIES);
        return createMockClientSession(client);
    }

    private ClientSession createMockClientSession(ClientFactoryManager client) throws Exception {
        return new ClientSessionImpl(client, Mockito.mock(IoSession.class)) {
            @Override
            protected IoWriteFuture sendClientIdentification() {
                return null;
            }

            @Override
            protected byte[] sendKexInit() throws IOException {
                return GenericUtils.EMPTY_BYTE_ARRAY;
            }

            @Override
            public void close() throws IOException {
                // ignored
            }
        };
    }
}
