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
package org.apache.sshd.common.cipher;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.jcraft.jsch.JSch;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * Test Cipher algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class CipherTest extends BaseTestSupport {
    private static final Integer NUM_LOADTEST_ROUNDS = 100000;

    /*
     * NOTE !!! order is important since we build from it the C2S/S2C ciphers proposal
     */
    @SuppressWarnings("deprecation")
    private static final List<Object[]> PARAMETERS = Collections.unmodifiableList(
            Arrays.asList(
                    new Object[] { BuiltinCiphers.aes128cbc, com.jcraft.jsch.jce.AES128CBC.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.aes128ctr, com.jcraft.jsch.jce.AES128CTR.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.tripledescbc, com.jcraft.jsch.jce.TripleDESCBC.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.blowfishcbc, com.jcraft.jsch.jce.BlowfishCBC.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.aes192cbc, com.jcraft.jsch.jce.AES192CBC.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.aes192ctr, com.jcraft.jsch.jce.AES192CTR.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.aes256cbc, com.jcraft.jsch.jce.AES256CBC.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.aes256ctr, com.jcraft.jsch.jce.AES256CTR.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.arcfour128, com.jcraft.jsch.jce.ARCFOUR128.class, NUM_LOADTEST_ROUNDS },
                    new Object[] { BuiltinCiphers.arcfour256, com.jcraft.jsch.jce.ARCFOUR256.class, NUM_LOADTEST_ROUNDS }));

    private static final List<NamedResource> TEST_CIPHERS = Collections.unmodifiableList(
            Stream.concat(PARAMETERS.stream()
                    .map(params -> (NamedResource) params[0]), Stream.of(BuiltinCiphers.none))
                    .collect(Collectors.toList()));

    private static final String CRYPT_NAMES = NamedResource.getNames(TEST_CIPHERS);
    private static SshServer sshd;
    private static int port;

    private final Random random = CommonTestSupportUtils.getRandomizerInstance();
    private final BuiltinCiphers builtInCipher;
    private final Class<? extends com.jcraft.jsch.Cipher> jschCipher;
    private final int loadTestRounds;

    public CipherTest(
                      BuiltinCiphers builtInCipher,
                      Class<? extends com.jcraft.jsch.Cipher> jschCipher,
                      int loadTestRounds) {
        this.builtInCipher = builtInCipher;
        this.jschCipher = jschCipher;
        this.loadTestRounds = loadTestRounds;
    }

    @Parameters(name = "cipher={0}, load={2}")
    public static Collection<Object[]> parameters() {
        return PARAMETERS;
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        JSchLogger.init();
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(CipherTest.class);
        sshd.start();
        port = sshd.getPort();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }
    }

    @Test
    public void testBuiltinCipherSession() throws Exception {
        Assume.assumeTrue("No internal support for " + builtInCipher.getName(),
                builtInCipher.isSupported() && checkCipher(jschCipher.getName()));
        sshd.setCipherFactories(Collections.singletonList(builtInCipher));
        runJschTest(port);
    }

    private void runJschTest(int port) throws Exception {
        JSch sch = new JSch();
        JSch.setConfig("cipher.s2c", CRYPT_NAMES);
        JSch.setConfig("cipher.c2s", CRYPT_NAMES);
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, port);
        s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
        s.connect();

        try {
            com.jcraft.jsch.Channel c = s.openChannel(Channel.CHANNEL_SHELL);
            c.connect();

            try (OutputStream os = c.getOutputStream();
                 InputStream is = c.getInputStream()) {
                String expected = "this is my command\n";
                byte[] expData = expected.getBytes(StandardCharsets.UTF_8);
                byte[] actData = new byte[expData.length + Long.SIZE /* just in case */];
                for (int i = 0; i < 10; i++) {
                    os.write(expData);
                    os.flush();

                    int len = is.read(actData);
                    String actual = new String(actData, 0, len, StandardCharsets.UTF_8);
                    assertEquals("Mismatched command at iteration " + i, expected, actual);
                }
            } finally {
                c.disconnect();
            }
        } finally {
            s.disconnect();
        }
    }

    @Test
    public void testCipherLoad() throws Exception {
        Assume.assumeTrue("No internal support for " + builtInCipher.getName(), builtInCipher.isSupported());
        loadTest(builtInCipher, random, loadTestRounds);
    }

    private static void loadTest(
            NamedFactory<Cipher> factory, Random random, int numRounds)
            throws Exception {
        Cipher cipher = factory.create();
        byte[] key = new byte[cipher.getKdfSize()];
        byte[] iv = new byte[cipher.getIVSize()];
        random.fill(key, 0, key.length);
        random.fill(iv, 0, iv.length);
        cipher.init(Cipher.Mode.Encrypt, key, iv);

        byte[] input = new byte[BufferUtils.getNextPowerOf2(cipher.getCipherBlockSize())];
        random.fill(input, 0, input.length);
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < numRounds; i++) {
            cipher.update(input, 0, input.length);
        }
        long t1 = System.currentTimeMillis();
        System.err.append(CipherTest.class.getSimpleName())
                .append(" - ").append(factory.getName())
                .append('[').append(Integer.toString(numRounds)).append(']')
                .append(": ").append(Long.toString(t1 - t0)).println(" ms");
    }

    static boolean checkCipher(String cipher) {
        try {
            Class<?> c = Class.forName(cipher);
            com.jcraft.jsch.Cipher jschCipher = ReflectionUtils.newInstance(c, com.jcraft.jsch.Cipher.class);
            jschCipher.init(com.jcraft.jsch.Cipher.ENCRYPT_MODE,
                    new byte[jschCipher.getBlockSize()],
                    new byte[jschCipher.getIVSize()]);
            return true;
        } catch (Exception e) {
            System.err.println("checkCipher(" + cipher + ")"
                               + " " + e.getClass().getSimpleName()
                               + ": " + e.getMessage());
            return false;
        }
    }
}
