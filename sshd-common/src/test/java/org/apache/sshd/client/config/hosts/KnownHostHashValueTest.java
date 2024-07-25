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
import java.util.Collection;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class KnownHostHashValueTest extends JUnitTestSupport {
    private String hostName;
    private int port;
    private String hashValue;
    private KnownHostHashValue hash;

    public void initKnownHostHashValueTest(String hostName, int port, String hashValue) {
        this.hostName = hostName;
        this.port = port;
        this.hashValue = hashValue;
        this.hash = KnownHostHashValue.parse(hashValue);
    }

    public static Collection<Object[]> parameters() {
        return Arrays.asList(
                // line generated `ssh xenon@localhost -p 10022 hostname` (SSH-2.0-OpenSSH_7.5)
                new Object[] {
                        "localhost", 10022,
                        "|1|qhjoqX12EcnwZO3KNbpoFbxrdYE=|J+voEFzRbRL49TiHV+jbUfaS+kg=" },
                // line generated `ssh xenon@localhost hostname` (SSH-2.0-OpenSSH_7.5)
                new Object[] {
                        "localhost", SshConstants.DEFAULT_PORT,
                        "|1|vLQs+atPgodQmPes21ZaMSgLD0s=|A2K2Ym0ZPtQmD8kB3FVViQvQ7qQ=" },
                new Object[] {
                        "192.168.1.61", SshConstants.DEFAULT_PORT,
                        "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=" });
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "host={0}, port={1}, hash={2}")
    public void decodeEncode(String hostName, int port, String hashValue) {
        initKnownHostHashValueTest(hostName, port, hashValue);
        assertSame(KnownHostHashValue.DEFAULT_DIGEST, hash.getDigester(), "Mismatched digester");
        assertEquals(hashValue, hash.toString(), "Mismatched encoded form");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "host={0}, port={1}, hash={2}")
    public void hostMatch(String hostName, int port, String hashValue) {
        initKnownHostHashValueTest(hostName, port, hashValue);
        assertTrue(hash.isHostMatch(hostName, port), "Specified host does not match");
        assertFalse(hash.isHostMatch(getCurrentTestName(), port), "Unexpected host match");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "host={0}, port={1}, hash={2}")
    public void calculateHashValue(String hostName, int port, String hashValue) throws Exception {
        initKnownHostHashValueTest(hostName, port, hashValue);
        byte[] expected = hash.getDigestValue();
        byte[] actual = KnownHostHashValue.calculateHashValue(
                hostName, port, hash.getDigester(), hash.getSaltValue());
        assertArrayEquals(expected, actual, "Mismatched hash value");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[host=" + hostName
               + ", port=" + port
               + ", hashValue=" + hashValue
               + "]";
    }
}
