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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class KnownHostHashValueTest extends JUnitTestSupport {
    private final String hostName;
    private final int port;
    private final String hashValue;
    private final KnownHostHashValue hash;

    public KnownHostHashValueTest(String hostName, int port, String hashValue) {
        this.hostName = hostName;
        this.port = port;
        this.hashValue = hashValue;
        this.hash = KnownHostHashValue.parse(hashValue);
    }

    @Parameters(name = "host={0}, port={1}, hash={2}")
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

    @Test
    public void testDecodeEncode() {
        assertSame("Mismatched digester", KnownHostHashValue.DEFAULT_DIGEST, hash.getDigester());
        assertEquals("Mismatched encoded form", hashValue, hash.toString());
    }

    @Test
    public void testHostMatch() {
        assertTrue("Specified host does not match", hash.isHostMatch(hostName, port));
        assertFalse("Unexpected host match", hash.isHostMatch(getCurrentTestName(), port));
    }

    @Test
    public void testCalculateHashValue() throws Exception {
        byte[] expected = hash.getDigestValue();
        byte[] actual = KnownHostHashValue.calculateHashValue(
                hostName, port, hash.getDigester(), hash.getSaltValue());
        assertArrayEquals("Mismatched hash value", expected, actual);
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
