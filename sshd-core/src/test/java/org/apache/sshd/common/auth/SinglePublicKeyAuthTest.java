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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SinglePublicKeyAuthTest extends BaseTestSupport {
    private SshServer sshd;
    private int port;
    private final KeyPair pairRsaGood;
    private KeyPair pairRsaBad;
    private PublickeyAuthenticator delegate;

    public SinglePublicKeyAuthTest() throws IOException, GeneralSecurityException {
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm(KeyUtils.RSA_ALGORITHM);
        pairRsaBad = provider.loadKey(null, KeyPairProvider.SSH_RSA);
        KeyPairProvider badKeys = createTestHostKeyProvider();
        pairRsaGood = badKeys.loadKey(null, KeyPairProvider.SSH_RSA);
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        PropertyResolverUtils.updateProperty(sshd, ServerAuthenticationManager.AUTH_METHODS, UserAuthPublicKeyFactory.NAME);
        sshd.setPublickeyAuthenticator((username, key, session) -> delegate.authenticate(username, key, session));
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
        ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<>();
        TestCachingPublicKeyAuthenticator auth = new TestCachingPublicKeyAuthenticator((username, key, session) -> {
            String fp = KeyUtils.getFingerPrint(key);
            AtomicInteger counter = count.computeIfAbsent(fp, k -> new AtomicInteger());
            counter.incrementAndGet();
            return key.equals(pairRsaGood.getPublic());
        });
        delegate = auth;

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPublicKeyIdentity(pairRsaBad);
                session.addPublicKeyIdentity(pairRsaGood);
                session.auth().verify(5L, TimeUnit.SECONDS);

                assertEquals("Mismatched authentication invocations count", 2, count.size());

                Map<Session, Map<PublicKey, Boolean>> cache = auth.getCache();
                assertEquals("Mismatched cache size", 1, cache.size());

                String fpBad = KeyUtils.getFingerPrint(pairRsaBad.getPublic());
                AtomicInteger badCounter = count.get(fpBad);
                assertNotNull("Missing bad public key", badCounter);
                assertEquals("Mismatched bad key authentication attempts", 1, badCounter.get());

                String fpGood = KeyUtils.getFingerPrint(pairRsaGood.getPublic());
                AtomicInteger goodCounter = count.get(fpGood);
                assertNotNull("Missing good public key", goodCounter);
                assertEquals("Mismatched good key authentication attempts", 1, goodCounter.get());
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testPublicKeyAuthWithoutCache() throws Exception {
        ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<>();
        delegate = (username, key, session) -> {
            String fp = KeyUtils.getFingerPrint(key);
            AtomicInteger counter = count.computeIfAbsent(fp, k -> new AtomicInteger());
            counter.incrementAndGet();
            return key.equals(pairRsaGood.getPublic());
        };

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPublicKeyIdentity(pairRsaBad);
                session.addPublicKeyIdentity(pairRsaGood);

                AuthFuture auth = session.auth();
                assertTrue("Failed to authenticate on time", auth.await(5L, TimeUnit.SECONDS));
                assertTrue("Authentication failed", auth.isSuccess());
            } finally {
                client.stop();
            }
        }

        assertEquals("Mismatched attempted keys count", 2, count.size());

        String badFingerPrint = KeyUtils.getFingerPrint(pairRsaBad.getPublic());
        Number badIndex = count.get(badFingerPrint);
        assertNotNull("Missing bad RSA key", badIndex);
        assertEquals("Mismatched attempt index for bad key", 1, badIndex.intValue());

        String goodFingerPrint = KeyUtils.getFingerPrint(pairRsaGood.getPublic());
        Number goodIndex = count.get(goodFingerPrint);
        assertNotNull("Missing good RSA key", goodIndex);
        assertEquals("Mismatched attempt index for good key", 2, goodIndex.intValue());
    }

    public static class TestCachingPublicKeyAuthenticator extends CachingPublicKeyAuthenticator {
        private final Map<Session, Map<PublicKey, Boolean>> cache = new ConcurrentHashMap<>();

        public TestCachingPublicKeyAuthenticator(PublickeyAuthenticator authenticator) {
            super(authenticator);
        }

        public Map<Session, Map<PublicKey, Boolean>> getCache() {
            return cache;
        }

        @Override
        protected Map<PublicKey, Boolean> resolveCachedResults(String username, PublicKey key, ServerSession session) {
            Map<PublicKey, Boolean> map = cache.computeIfAbsent(session, s -> new ConcurrentHashMap<>());
            return session.computeAttributeIfAbsent(CACHE_ATTRIBUTE, k -> map);
        }
    }
}