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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.util.Arrays;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.UserInfo;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Random;
import org.apache.sshd.common.cipher.AES128CBC;
import org.apache.sshd.common.cipher.AES192CBC;
import org.apache.sshd.common.cipher.AES256CBC;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.cipher.TripleDESCBC;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test Cipher algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CipherTest {

    private SshServer sshd;
    private int port;

    @Test
    public void testAES128CBC() throws Exception {
        setUp(new AES128CBC.Factory());
        runTest();
    }

    @Test
    @Ignore("AES192CBC is not always available by default")
    public void testAES192CBC() throws Exception {
        setUp(new AES192CBC.Factory());
        runTest();
    }

    @Test
    @Ignore("AES256CBC is not always available by default")
    public void testAES256CBC() throws Exception {
        setUp(new AES256CBC.Factory());
        runTest();
    }

    @Test
    public void testBlowfishCBC() throws Exception {
        setUp(new BlowfishCBC.Factory());
        runTest();
    }

    @Test
    public void testTripleDESCBC() throws Exception {
        setUp(new TripleDESCBC.Factory());
        runTest();
    }

    @Test
    public void loadTest() throws Exception {
        Random random = new BouncyCastleRandom();
        loadTest(new AES128CBC.Factory(), random);
        loadTest(new BlowfishCBC.Factory(), random);
        loadTest(new TripleDESCBC.Factory(), random);
    }

    protected void loadTest(NamedFactory<Cipher> factory, Random random) throws Exception {
        Cipher cipher = factory.create();
        byte[] key = new byte[cipher.getBlockSize()];
        byte[] iv = new byte[cipher.getIVSize()];
        random.fill(key, 0, key.length);
        random.fill(iv, 0, iv.length);
        cipher.init(Cipher.Mode.Encrypt, key, iv);

        byte[] input = new byte[cipher.getBlockSize()];
        random.fill(input, 0, input.length);
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < 100000; i++) {
            cipher.update(input, 0, input.length);
        }
        long t1 = System.currentTimeMillis();
        System.err.println(factory.getName() + ": " + (t1 - t0) + " ms");
    }


    protected void setUp(NamedFactory<org.apache.sshd.common.Cipher> cipher) throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setCipherFactories(Arrays.<NamedFactory<org.apache.sshd.common.Cipher>>asList(cipher));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop();
        }
    }

    protected void runTest() throws Exception {
        JSch sch = new JSch();
        JSch.setConfig("cipher.s2c", "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,none");
        JSch.setConfig("cipher.c2s", "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,none");
        sch.setLogger(new Logger() {
            public boolean isEnabled(int i) {
                return true;
            }
            public void log(int i, String s) {
                System.out.println("Log(jsch," + i + "): " + s);
            }
        });
        com.jcraft.jsch.Session s = sch.getSession("smx", "localhost", port);
        s.setUserInfo(new UserInfo() {
            public String getPassphrase() {
                return null;
            }
            public String getPassword() {
                return "smx";
            }
            public boolean promptPassword(String message) {
                return true;
            }
            public boolean promptPassphrase(String message) {
                return false;
            }
            public boolean promptYesNo(String message) {
                return true;
            }
            public void showMessage(String message) {
            }
        });
        s.connect();
        com.jcraft.jsch.Channel c = s.openChannel("shell");
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        for (int i = 0; i < 10; i++) {
            os.write("this is my command\n".getBytes());
            os.flush();
            byte[] data = new byte[512];
            int len = is.read(data);
            String str = new String(data, 0, len);
            assertEquals("this is my command\n", str);
        }
        c.disconnect();
        s.disconnect();
    }
}
