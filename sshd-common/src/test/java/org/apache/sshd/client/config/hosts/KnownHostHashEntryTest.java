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

package org.apache.sshd.client.config.hosts;

import java.util.Arrays;
import java.util.List;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class KnownHostHashEntryTest extends JUnitTestSupport {
    private final String host;
    private final int port;
    private final String comment;
    private final String line;

    public KnownHostHashEntryTest(String host, int port, String hashValue, String keyType, String keyData, String comment) {
        this.host = host;
        this.port = port;
        this.comment = comment;
        this.line = GenericUtils.join(new Object[] { hashValue, keyType, keyData, comment }, ' ');
    }

    @Parameters(name = "{5}")
    public static List<Object[]> parameters() {
        return Arrays.asList(
                // line generated `ssh xenon@localhost hostname` (SSH-2.0-OpenSSH_7.5)
                new Object[] {
                        "localhost", SshConstants.DEFAULT_PORT,
                        "|1|vLQs+atPgodQmPes21ZaMSgLD0s=|A2K2Ym0ZPtQmD8kB3FVViQvQ7qQ=", "ecdsa-sha2-nistp256",
                        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJTsDTYFSYyRMlOec6JBfC8dEFqHNNWu7n8N0niS1zmHpggX+L4cndxhJPE0ILi9otHO7h0mp0cmqqho2tsX8lc=",
                        "xenon@localhost"
                },
                // line generated `ssh xenon@localhost -p 10022 hostname` (SSH-2.0-OpenSSH_7.5)
                new Object[] {
                        "localhost", 10022,
                        "|1|qhjoqX12EcnwZO3KNbpoFbxrdYE=|J+voEFzRbRL49TiHV+jbUfaS+kg=", "ecdsa-sha2-nistp256",
                        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJTsDTYFSYyRMlOec6JBfC8dEFqHNNWu7n8N0niS1zmHpggX+L4cndxhJPE0ILi9otHO7h0mp0cmqqho2tsX8lc=",
                        "xenon@localhost:10022"
                });
    }

    @Test
    public void testHostHashMatchOnSamePort() {
        KnownHostEntry entry = KnownHostEntry.parseKnownHostEntry(line);
        assertTrue(entry.isHostMatch(host, port));
    }

    @Test
    public void testHostHashNotMatchOnDifferentPort() {
        KnownHostEntry entry = KnownHostEntry.parseKnownHostEntry(line);
        assertFalse(entry.isHostMatch(host, port / 2));
    }

    @Test
    public void testHostHashMatchOnDefaultPort() {
        Assume.assumeTrue("No-default port used", port == SshConstants.DEFAULT_PORT);
        KnownHostEntry entry = KnownHostEntry.parseKnownHostEntry(line);
        assertTrue(entry.isHostMatch(host, 0));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + comment + "]";
    }
}
