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
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EcdsaTest extends BaseTest {

    private SshServer sshd;
    private SshClient client;
    private int port;

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
//        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setSessionFactory(new org.apache.sshd.server.session.SessionFactory());
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
    public void testECDSA_SHA2_NISTP256() throws Exception {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        sshd.setKeyPairProvider(new AbstractKeyPairProvider() {
            @Override
            public Iterable<KeyPair> loadKeys() {
                try {
                    ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
                    KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("ECDSA");
                    generator.initialize(ecGenSpec, new SecureRandom());
                    KeyPair kp = generator.generateKeyPair();
                    return Collections.singleton(kp);
                } catch (Exception e) {
                    throw new RuntimeSshException(e);
                }
            }
        });
        sshd.start();
        port = sshd.getPort();

        client = SshClient.setUpDefaultClient();
        client.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                BuiltinSignatures.nistp256,
                BuiltinSignatures.nistp384,
                BuiltinSignatures.nistp521));
        client.start();
        try(ClientSession s = client.connect("smx", "localhost", port).await().getSession()) {
            s.addPasswordIdentity("smx");
            s.auth().verify(5L, TimeUnit.SECONDS);
        }
    }

    @Test
    public void testEcdsaPublicKeyAuth() throws Exception {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("ECDSA");
        generator.initialize(ecGenSpec, new SecureRandom());
        KeyPair kp = generator.generateKeyPair();


        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return true;
            }
        });
        sshd.start();
        port  = sshd.getPort();

        client = SshClient.setUpDefaultClient();
        client.start();
        
        try(ClientSession s = client.connect("smx", "localhost", port).await().getSession()) {
            s.addPublicKeyIdentity(kp);
            s.auth().verify(5L, TimeUnit.SECONDS);
        }
    }
}
