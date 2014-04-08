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
package org.apache.sshd;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.util.KeyUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.auth.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SinglePublicKeyAuthTest extends BaseTest {

    private SshServer sshd;
    private int port = 0;
    private KeyPair pairRsa = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
    private KeyPair pairRsaBad = new SimpleGeneratorHostKeyProvider(null, "RSA").loadKey(KeyPairProvider.SSH_RSA);
    private PublickeyAuthenticator delegate;

    @Before
    public void setUp() throws Exception {
        port = Utils.getFreePort();
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setCommandFactory(new CommandFactory() {
            public Command createCommand(String command) {
                return new UnknownCommand(command);
            }
        });
        sshd.getProperties().put(SshServer.AUTH_METHODS, "publickey");
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return delegate.authenticate(username, key, session);
            }
        });
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
            Thread.sleep(50);
        }
    }

    @Test
    public void testPublicKeyAuthWithCache() throws Exception {
        final ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<String, AtomicInteger>();
        TestCachingPublicKeyAuthenticator auth = new TestCachingPublicKeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key,
                                        ServerSession session) {
                count.putIfAbsent(KeyUtils.getFingerPrint(key), new AtomicInteger());
                count.get(KeyUtils.getFingerPrint(key)).incrementAndGet();
                return key.equals(pairRsa.getPublic());
            }
        });
        delegate = auth;
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPublicKeyIdentity(pairRsaBad);
        session.addPublicKeyIdentity(pairRsa);
        assertTrue(session.auth().await().isSuccess());
        assertEquals(2, count.size());
        assertTrue(count.containsKey(KeyUtils.getFingerPrint(pairRsaBad.getPublic())));
        assertTrue(count.containsKey(KeyUtils.getFingerPrint(pairRsa.getPublic())));
        assertEquals(1, count.get(KeyUtils.getFingerPrint(pairRsaBad.getPublic())).get());
        assertEquals(1, count.get(KeyUtils.getFingerPrint(pairRsa.getPublic())).get());
        client.close(false).await();
        Thread.sleep(100);
        assertTrue(auth.getCache().isEmpty());
    }

    @Test
    public void testPublicKeyAuthWithoutCache() throws Exception {
        final ConcurrentHashMap<String, AtomicInteger> count = new ConcurrentHashMap<String, AtomicInteger>();
        delegate = new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key,
                                        ServerSession session) {
                count.putIfAbsent(KeyUtils.getFingerPrint(key), new AtomicInteger());
                count.get(KeyUtils.getFingerPrint(key)).incrementAndGet();
                return key.equals(pairRsa.getPublic());
            }
        };
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPublicKeyIdentity(pairRsaBad);
        session.addPublicKeyIdentity(pairRsa);
        assertTrue(session.auth().await().isSuccess());
        assertEquals(2, count.size());
        assertTrue(count.containsKey(KeyUtils.getFingerPrint(pairRsaBad.getPublic())));
        assertTrue(count.containsKey(KeyUtils.getFingerPrint(pairRsa.getPublic())));
        assertEquals(1, count.get(KeyUtils.getFingerPrint(pairRsaBad.getPublic())).get());
        assertEquals(2, count.get(KeyUtils.getFingerPrint(pairRsa.getPublic())).get());
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


