/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.auth.UserAuthPublicKeyFactory;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SinglePublicKeyAuthTest extends BaseTestSupport {

    private SshServer sshd;
    private int port = 0;
    private KeyPair pairRsa = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
    private KeyPair pairRsaBad;
    private PublickeyAuthenticator delegate;

    public SinglePublicKeyAuthTest() {
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm("RSA");
        pairRsaBad = provider.loadKey(KeyPairProvider.SSH_RSA);
    }

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setCommandFactory(new CommandFactory() {
            @Override
            public Command createCommand(String command) {
                return new UnknownCommand(command);
            }
        });
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthPublicKeyFactory.NAME);
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @SuppressWarnings("synthetic-access")
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return delegate.authenticate(username, key, session);
            }
        });
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testPublicKeyAuthWithCache() throws Exception {
        final ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<String, AtomicInteger>();
        TestCachingPublicKeyAuthenticator auth = new TestCachingPublicKeyAuthenticator(new PublickeyAuthenticator() {
            @SuppressWarnings("synthetic-access")
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                count.putIfAbsent(KeyUtils.getFingerPrint(key), new AtomicInteger());
                count.get(KeyUtils.getFingerPrint(key)).incrementAndGet();
                return key.equals(pairRsa.getPublic());
            }
        });
        delegate = auth;

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPublicKeyIdentity(pairRsaBad);
                session.addPublicKeyIdentity(pairRsa);
                session.auth().verify(5L, TimeUnit.SECONDS);

                assertEquals(2, count.size());
                assertTrue(count.containsKey(KeyUtils.getFingerPrint(pairRsaBad.getPublic())));
                assertTrue(count.containsKey(KeyUtils.getFingerPrint(pairRsa.getPublic())));
                assertEquals(1, count.get(KeyUtils.getFingerPrint(pairRsaBad.getPublic())).get());
                assertEquals(1, count.get(KeyUtils.getFingerPrint(pairRsa.getPublic())).get());
                client.close(false).await();
            } finally {
                client.stop();
            }
        }

        Thread.sleep(100);
        assertTrue(auth.getCache().isEmpty());
    }

    @Test
    public void testPublicKeyAuthWithoutCache() throws Exception {
        final ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<String, AtomicInteger>();
        delegate = new PublickeyAuthenticator() {
            @SuppressWarnings("synthetic-access")
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                count.putIfAbsent(KeyUtils.getFingerPrint(key), new AtomicInteger());
                count.get(KeyUtils.getFingerPrint(key)).incrementAndGet();
                return key.equals(pairRsa.getPublic());
            }
        };

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPublicKeyIdentity(pairRsaBad);
                session.addPublicKeyIdentity(pairRsa);
                assertTrue("Failed to authenticate", session.auth().await().isSuccess());
            } finally {
                client.stop();
            }
        }

        assertEquals("Mismatched attempted keys count", 2, count.size());

        String badFingerPrint = KeyUtils.getFingerPrint(pairRsaBad.getPublic());
        Number badIndex = count.get(badFingerPrint);
        assertNotNull("Missing bad RSA key", badIndex);
        assertEquals("Mismatched attempt index for bad key", 1, badIndex.intValue());

        String goodFingerPrint = KeyUtils.getFingerPrint(pairRsa.getPublic());
        Number goodIndex = count.get(goodFingerPrint);
        assertNotNull("Missing good RSA key", goodIndex);
        assertEquals("Mismatched attempt index for good key", 2, goodIndex.intValue());
    }

    public static class TestCachingPublicKeyAuthenticator extends CachingPublicKeyAuthenticator {
        public TestCachingPublicKeyAuthenticator(PublickeyAuthenticator authenticator) {
            super(authenticator);
        }

        public Map<ServerSession, Map<PublicKey, Boolean>> getCache() {
            return cache;
        }
    }
}