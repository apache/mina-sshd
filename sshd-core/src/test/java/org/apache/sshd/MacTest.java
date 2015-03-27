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
import java.util.Arrays;

import com.jcraft.jsch.JSch;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Random;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Test Cipher algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MacTest extends BaseTest {

    private SshServer sshd;
    private int port;

    @Test
    public void testHMACMD5() throws Exception {
        setUp(BuiltinMacs.hmacmd5);
        runTest();
    }

    @Test
    public void testHMACMD596() throws Exception {
        setUp(BuiltinMacs.hmacmd596);
        runTest();
    }

    @Test
    public void testHMACSHA1() throws Exception {
        setUp(BuiltinMacs.hmacsha1);
        runTest();
    }

    @Test
    public void testHMACSHA196() throws Exception {
        setUp(BuiltinMacs.hmacsha196);
        runTest();
    }

    @Test
    public void testHMACSHA256() throws Exception {
        setUp(BuiltinMacs.hmacsha256);
        runTest();
    }

    @Test
    @Ignore("Lead to ArrayIndexOutOfBoundsException in JSch")
    public void testHMACSHA512() throws Exception {
        setUp(BuiltinMacs.hmacsha512);
        runTest();
    }

    @Test
    public void loadTest() throws Exception {
        Random random = new BouncyCastleRandom();
        loadTest(BuiltinCiphers.aes128cbc, random);
        loadTest(BuiltinCiphers.blowfishcbc, random);
        loadTest(BuiltinCiphers.tripledescbc, random);
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


    protected void setUp(NamedFactory<Mac> mac) throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setMacFactories(Arrays.<NamedFactory<Mac>>asList(mac));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        port  = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    protected void runTest() throws Exception {
        JSchLogger.init();
        JSch sch = new JSch();
        JSch.setConfig("cipher.s2c", "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,none");
        JSch.setConfig("cipher.c2s", "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,none");
        JSch.setConfig("mac.s2c", "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96,hmac-sha2-512");
        JSch.setConfig("mac.c2s", "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96,hmac-sha2-512");
        JSch.setConfig("hmac-sha2-512",  "com.jcraft.jsch.jce.HMACSHA512");
        com.jcraft.jsch.Session s = sch.getSession("smx", "localhost", port);
        try {
            s.setUserInfo(new SimpleUserInfo("smx"));
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
        } finally {
            s.disconnect();
        }
    }

    static boolean checkCipher(String cipher){
        try{
            Class c=Class.forName(cipher);
            com.jcraft.jsch.Cipher _c = (com.jcraft.jsch.Cipher)(c.newInstance());
            _c.init(com.jcraft.jsch.Cipher.ENCRYPT_MODE,
                    new byte[_c.getBlockSize()],
                    new byte[_c.getIVSize()]);
            return true;
        }
        catch(Exception e){
            return false;
        }
    }
}
