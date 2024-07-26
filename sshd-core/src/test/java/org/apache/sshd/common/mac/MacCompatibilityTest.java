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
package org.apache.sshd.common.mac;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.ConnectionInfo;
import com.jcraft.jsch.JSch;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test MAC algorithms with other known implementations.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class MacCompatibilityTest extends BaseTestSupport {
    private static final Collection<String> GANYMEDE_MACS = Collections.unmodifiableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, Connection.getAvailableMACs()));

    private static SshServer sshd;
    private static int port;

    private MacFactory factory;

    public static Collection<Object[]> parameters() {
        List<Object[]> ret = new ArrayList<>();
        for (MacFactory f : BuiltinMacs.VALUES) {
            if (!f.isSupported()) {
                outputDebugMessage("Skip unsupported MAC %s", f);
                continue;
            }

            // None of the implementations we use support encrypt-then-mac mode
            if (f.isEncryptThenMac()) {
                outputDebugMessage("Skip Encrypt-Then-Mac %s", f);
                continue;
            }

            String name = f.getName();
            // derive the JSCH implementation of the specific MAC
            int pos = name.indexOf('-');
            String remainder = name.substring(pos + 1);
            pos = remainder.indexOf('-');

            String className;
            if (pos < 0) {
                className = "HMAC" + remainder.toUpperCase();
            } else {
                String algorithm = remainder.substring(0, pos);
                remainder = remainder.substring(pos + 1);
                if ("sha2".equals(algorithm)) {
                    className = "HMACSHA" + remainder.toUpperCase();
                } else {
                    className = "HMAC" + algorithm.toUpperCase() + remainder.toUpperCase();
                }
            }

            ret.add(new Object[] { f, "com.jcraft.jsch.jce." + className });
        }

        return ret;
    }

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        JSchLogger.init();
        setupClientAndServer(MacCompatibilityTest.class);
    }

    private static void setupClientAndServer(Class<?> anchor) throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(anchor);

        // Need to use RSA since Ganymede does not support EC
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm(KeyUtils.RSA_ALGORITHM);
        provider.setKeySize(1024);

        Path targetDir = CommonTestSupportUtils.detectTargetFolder(anchor);
        provider.setPath(targetDir.resolve(anchor.getSimpleName() + "-key"));

        sshd.setKeyPairProvider(provider);
        sshd.start();
        port = sshd.getPort();
    }

    @AfterAll
    static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "factory={0}")
    public void withJSCH(MacFactory factory, String jschMacClass) throws Exception {
        sshd.setMacFactories(Collections.singletonList(factory));
        String macName = factory.getName();
        Assumptions.assumeTrue(!BuiltinMacs.hmacsha512.equals(factory), "Known JSCH bug with " + macName);

        JSch sch = new JSch();
        Map<String, String> values = new HashMap<>();
        values.put("cipher.s2c", JSch.getConfig("cipher.s2c"));
        values.put("cipher.c2s", JSch.getConfig("cipher.s2c"));
        values.put("mac.s2c", JSch.getConfig("mac.s2c"));
        values.put("mac.c2s", JSch.getConfig("mac.s2c"));
        values.put(macName, JSch.getConfig(macName));
        try {
            JSch.setConfig("cipher.s2c", "aes128-ctr,aes192-ctr,aes256-ctr,none");
            JSch.setConfig("cipher.c2s", "aes128-ctr,aes192-ctr,aes256-ctr,none");
            JSch.setConfig("mac.s2c", macName);
            JSch.setConfig("mac.c2s", macName);
            JSch.setConfig(macName, jschMacClass);

            com.jcraft.jsch.Session session = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, port);
            try {
                session.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
                session.connect();

                com.jcraft.jsch.Channel channel = session.openChannel(Channel.CHANNEL_SHELL);
                channel.connect();

                try (OutputStream stdin = channel.getOutputStream();
                     InputStream stdout = channel.getInputStream();
                     InputStream stderr = channel.getExtInputStream()) {
                    runShellTest(stdin, stdout);
                } finally {
                    channel.disconnect();
                }
            } finally {
                session.disconnect();
            }
        } finally {
            for (Map.Entry<String, String> item : values.entrySet()) {
                JSch.setConfig(item.getKey(), item.getValue());
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "factory={0}")
    public void withGanymede(MacFactory factory, String jschMacClass) throws Exception {
        sshd.setMacFactories(Collections.singletonList(factory));
        String macName = factory.getName();
        Assumptions.assumeTrue(GANYMEDE_MACS.contains(macName), "Factory not supported: " + macName);

        ch.ethz.ssh2.log.Logger.enabled = true;
        Connection conn = new Connection(TEST_LOCALHOST, port);
        try {
            conn.setClient2ServerMACs(new String[] { macName });

            ConnectionInfo info = conn.connect(null,
                    (int) TimeUnit.SECONDS.toMillis(5L), (int) TimeUnit.SECONDS.toMillis(11L));
            outputDebugMessage("Connected: kex=%s, key-type=%s, c2senc=%s, s2cenc=%s, c2mac=%s, s2cmac=%s",
                    info.keyExchangeAlgorithm, info.serverHostKeyAlgorithm,
                    info.clientToServerCryptoAlgorithm, info.serverToClientCryptoAlgorithm,
                    info.clientToServerMACAlgorithm, info.serverToClientMACAlgorithm);
            assertTrue(conn.authenticateWithPassword(getCurrentTestName(), getCurrentTestName()), "Failed to authenticate");

            ch.ethz.ssh2.Session session = conn.openSession();
            try {
                session.startShell();
                try (OutputStream stdin = session.getStdin();
                     InputStream stdout = session.getStdout();
                     InputStream stderr = session.getStderr()) {
                    runShellTest(stdin, stdout);
                }
            } finally {
                session.close();
            }
        } finally {
            conn.close();
        }
    }

    private void runShellTest(OutputStream stdin, InputStream stdout) throws IOException {
        String expected = "this is my command\n";
        byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] data = new byte[bytes.length + Long.SIZE];
        for (int index = 1; index <= 10; index++) {
            stdin.write(bytes);
            stdin.flush();

            int len = stdout.read(data);
            String str = new String(data, 0, len, StandardCharsets.UTF_8);
            assertEquals(expected, str, "Mismatched data at iteration " + index);
        }
    }
}
