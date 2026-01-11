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
package org.apache.sshd.server.shell;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ProcessShellTest extends BaseTestSupport {
    private SshClient client;

    public ProcessShellTest() {
        super();
    }

    @BeforeEach
    public void setUp() throws Exception {
        client = CoreTestSupportUtils.setupTestClient(getClass());
        client.start();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.stop();
        }
    }

    /**
     * Verifies that characters sent to the shell are returned exactly as they were sent, without any modifications or
     * redundant echoes from the server.
     * <p>
     * This test ensures that the SSH server does not inject extra characters (like manual echoes) into the data stream.
     * It verifies that characters sent to the shell are returned without any modifications. If the server were to
     * return modified characters or extra echoes, it would indicate a failure in the I/O bridging logic.
     * </p>
     * <p>
     * The test relies on {@code cat} as a shell because it is a simple, standard Linux utility that acts as a
     * transparent bridge, reading from STDIN and writing to STDOUT without any internal processing, echoing, or
     * modifications to the character stream. This allows the test to isolate and verify the server's behavior without
     * interference from the shell process itself.
     * </p>
     * <p>
     * Note: This test is skipped on Windows because {@code cat} is not natively available. Since the core logic being
     * tested is platform-independent Java, verifying it on Unix-like systems is sufficient.
     * </p>
     *
     * @throws Exception If failed
     */
    @Test
    void testNoRedundantEchoOnStderr() throws Exception {
        if (OsUtils.isWin32()) {
            return;
        }

        try (SshServer localSshd = CoreTestSupportUtils.setupTestServer(getClass())) {
            localSshd.setShellFactory(new ProcessShellFactory("cat", "cat"));
            localSshd.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", localSshd.getPort())
                    .verify(10_000).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(10_000);

                try (ChannelShell channel = session.createShellChannel();
                     ByteArrayOutputStream out = new ByteArrayOutputStream();
                     ByteArrayOutputStream err = new ByteArrayOutputStream()) {
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open().verify(10_000);

                    OutputStream pipe = channel.getInvertedIn();
                    pipe.write("hello\n".getBytes(StandardCharsets.UTF_8));
                    pipe.flush();

                    Thread.sleep(1000);

                    String stderr = err.toString(StandardCharsets.UTF_8.name());
                    assertFalse(stderr.contains("hello"), "Redundant echo detected on stderr: " + stderr);

                    String stdout = out.toString(StandardCharsets.UTF_8.name());
                    assertTrue(stdout.contains("hello"), "Output should contain 'hello': " + stdout);
                }
            } finally {
                localSshd.stop(true);
            }
        }
    }
}
