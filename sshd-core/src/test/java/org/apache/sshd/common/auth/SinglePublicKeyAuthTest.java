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
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class SinglePublicKeyAuthTest extends BaseTestSupport {
    private SshServer sshd;
    private int port;
    private final KeyPair kpGood;
    private final KeyPair kpBad;
    private PublickeyAuthenticator delegate;

    public SinglePublicKeyAuthTest() throws IOException, GeneralSecurityException {
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm(CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM);
        provider.setKeySize(CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_SIZE);
        provider.setPath(detectTargetFolder().resolve(getClass().getSimpleName() + "-key"));

        kpBad = provider.loadKey(null, CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_TYPE);
        KeyPairProvider badKeys = createTestHostKeyProvider();
        kpGood = badKeys.loadKey(null, CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_TYPE);
    }

    @BeforeAll // FIXME inexplicably these tests fail without BC since SSHD-1004
    static void ensureBouncycastleRegistered() {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "Requires BC security provider");
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestFullSupportServer();
        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthPublicKeyFactory.NAME);
        sshd.setPublickeyAuthenticator((username, key, session) -> delegate.authenticate(username, key, session));
        sshd.start();
        port = sshd.getPort();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    void publicKeyAuthWithCache() throws Exception {
        ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<>();
        TestCachingPublicKeyAuthenticator auth = new TestCachingPublicKeyAuthenticator((username, key, session) -> {
            String fp = KeyUtils.getFingerPrint(key);
            AtomicInteger counter = count.computeIfAbsent(fp, k -> new AtomicInteger());
            counter.incrementAndGet();
            return key.equals(kpGood.getPublic());
        });
        delegate = auth;

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPublicKeyIdentity(kpBad);
                session.addPublicKeyIdentity(kpGood);
                session.auth().verify(AUTH_TIMEOUT);

                assertEquals(2, count.size(), "Mismatched authentication invocations count");

                Map<Session, Map<PublicKey, Boolean>> cache = auth.getCache();
                assertEquals(1, cache.size(), "Mismatched cache size");

                String fpBad = KeyUtils.getFingerPrint(kpBad.getPublic());
                AtomicInteger badCounter = count.get(fpBad);
                assertNotNull(badCounter, "Missing bad public key");
                assertEquals(1, badCounter.get(), "Mismatched bad key authentication attempts");

                String fpGood = KeyUtils.getFingerPrint(kpGood.getPublic());
                AtomicInteger goodCounter = count.get(fpGood);
                assertNotNull(goodCounter, "Missing good public key");
                assertEquals(1, goodCounter.get(), "Mismatched good key authentication attempts");
            } finally {
                client.stop();
            }
        }
    }

    @Test
    void publicKeyAuthWithoutCache() throws Exception {
        ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<>();
        delegate = (username, key, session) -> {
            String fp = KeyUtils.getFingerPrint(key);
            AtomicInteger counter = count.computeIfAbsent(fp, k -> new AtomicInteger());
            counter.incrementAndGet();
            return key.equals(kpGood.getPublic());
        };

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPublicKeyIdentity(kpBad);
                session.addPublicKeyIdentity(kpGood);

                AuthFuture auth = session.auth();
                assertTrue(auth.await(AUTH_TIMEOUT), "Failed to authenticate on time");
                assertTrue(auth.isSuccess(), "Authentication failed");
            } finally {
                client.stop();
            }
        }

        assertEquals(2, count.size(), "Mismatched attempted keys count");

        String badFingerPrint = KeyUtils.getFingerPrint(kpBad.getPublic());
        Number badIndex = count.get(badFingerPrint);
        assertNotNull(badIndex, "Missing bad key");
        assertEquals(1, badIndex.intValue(), "Mismatched attempt index for bad key");

        String goodFingerPrint = KeyUtils.getFingerPrint(kpGood.getPublic());
        Number goodIndex = count.get(goodFingerPrint);
        assertNotNull(goodIndex, "Missing good key");
        assertEquals(2, goodIndex.intValue(), "Mismatched attempt index for good key");
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
