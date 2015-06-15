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
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.ECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.PublickeyAuthenticator.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assume;
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
public class EcdsaTest extends BaseTestSupport {

    private SshServer sshd;
    private SshClient client;
    private int port;

    public EcdsaTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
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
        testECDSA_SHA2_NISTP_Curve(ECCurves.NISTP256);
    }

    @Test
    public void testECDSA_SHA2_NISTP384() throws Exception {
        testECDSA_SHA2_NISTP_Curve(ECCurves.NISTP384);
    }

    @Test
    public void testECDSA_SHA2_NISTP521() throws Exception {
        testECDSA_SHA2_NISTP_Curve(ECCurves.NISTP521);
    }

    private void testECDSA_SHA2_NISTP_Curve(final String curvName) throws Exception {
        Assume.assumeTrue("ECC not supported", SecurityUtils.hasEcc() || SecurityUtils.isBouncyCastleRegistered());
        sshd.setKeyPairProvider(new AbstractKeyPairProvider() {
                private final AtomicReference<Iterable<KeyPair>> keys=new AtomicReference<Iterable<KeyPair>>(null);
    
                @Override
                public Iterable<KeyPair> loadKeys() {
                    Iterable<KeyPair>   iter;
                    synchronized(keys) {
                        if ((iter=keys.get()) != null) {
                            return iter;
                        }
    
                        try {
                            Integer keySize = ECCurves.getCurveSize(curvName);
                            assertNotNull("No key size for curve=" + curvName, keySize);
                            KeyPair kp = ECDSAPublicKeyEntryDecoder.INSTANCE.generateKeyPair(keySize.intValue());
                            iter = Collections.singleton(kp);
                            keys.set(iter);
                        } catch (Exception e) {
                            throw new RuntimeSshException(e);
                        }
                    }
                    
                    return iter;
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
        try(ClientSession s = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(15L, TimeUnit.SECONDS);
        } finally {
            client.stop();
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
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.start();
        port  = sshd.getPort();

        client = SshClient.setUpDefaultClient();
        client.start();
        
        try(ClientSession s = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
            s.addPublicKeyIdentity(kp);
            s.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }
}
