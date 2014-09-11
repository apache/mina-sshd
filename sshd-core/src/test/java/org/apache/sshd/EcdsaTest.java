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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.sshd.client.SessionFactory;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureECDSA;
import org.apache.sshd.common.signature.SignatureRSA;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
        port = Utils.getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
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
        if (SecurityUtils.isBouncyCastleRegistered()) {
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

            client = SshClient.setUpDefaultClient();
            client.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureECDSA.NISTP256Factory(),
                    new SignatureECDSA.NISTP384Factory(),
                    new SignatureECDSA.NISTP521Factory()));
            client.start();
            ClientSession s = client.connect("smx", "localhost", port).await().getSession();
            s.addPasswordIdentity("smx");
            s.auth().verify();
        }
    }

    @Test
    public void testEcdsaPublicKeyAuth() throws Exception {
        if (SecurityUtils.isBouncyCastleRegistered()) {
            sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
            sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
                public boolean authenticate(String username, PublicKey key, ServerSession session) {
                    return true;
                }
            });
            sshd.start();

            client = SshClient.setUpDefaultClient();
            client.start();
            ClientSession s = client.connect("smx", "localhost", port).await().getSession();

            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("ECDSA");
            generator.initialize(ecGenSpec, new SecureRandom());
            KeyPair kp = generator.generateKeyPair();
            s.addPublicKeyIdentity(kp);
            s.auth().verify();
        }
    }

}
