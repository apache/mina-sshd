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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class EncryptThenMacTest extends BaseTestSupport {
    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    private MacFactory factory;

    public void initEncryptThenMacTest(MacFactory factory) throws Exception {
        this.factory = factory;
        sshd.setCipherFactories(Collections.singletonList(BuiltinCiphers.aes128ctr));
        client.setCipherFactories(Collections.singletonList(BuiltinCiphers.aes128ctr));
        sshd.setMacFactories(Collections.singletonList(this.factory));
        client.setMacFactories(Collections.singletonList(this.factory));
    }

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(EncryptThenMacTest.class);
        sshd.setKeyPairProvider(CommonTestSupportUtils.createTestHostKeyProvider(EncryptThenMacTest.class));
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(EncryptThenMacTest.class);
        client.start();
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

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    public static Collection<Object[]> parameters() {
        List<Object[]> ret = new ArrayList<>();
        for (MacFactory f : BuiltinMacs.VALUES) {
            if (!f.isSupported()) {
                outputDebugMessage("Skip unsupported MAC %s", f);
                continue;
            }

            // We want only encrypt-then-mac mode
            if (!f.isEncryptThenMac()) {
                outputDebugMessage("Skip Mac-Then-Encrypt %s", f);
                continue;
            }

            ret.add(new Object[] { f });
        }

        return ret;
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void clientConnection(MacFactory factory) throws Exception {
        initEncryptThenMacTest(factory);
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            String expected = factory.getName();
            for (KexProposalOption opt : KexProposalOption.MAC_PROPOSALS) {
                String actual = session.getNegotiatedKexParameter(opt);
                assertEquals(expected, actual, "Mismatched " + opt + " negotiation");
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + factory + "]";
    }
}
