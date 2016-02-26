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

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class KnownHostHashValueTest extends BaseTestSupport {
    private final String hostName;
    private final String hashValue;
    private final KnownHostHashValue hash;

    public KnownHostHashValueTest(String hostName, String hashValue) {
        this.hostName = hostName;
        this.hashValue = hashValue;
        this.hash = KnownHostHashValue.parse(hashValue);
    }

    @Parameters(name = "host={0}, hash={1}")
    public static Collection<Object[]> parameters() {
        return Arrays.<Object[]>asList(
                (Object[]) new String[]{"192.168.1.61", "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg="});
    }

    @Test
    public void testDecodeEncode() {
        assertSame("Mismatched digester", KnownHostHashValue.DEFAULT_DIGEST, hash.getDigester());
        assertEquals("Mismatched encoded form", hashValue, hash.toString());
    }

    @Test
    public void testHostMatch() {
        assertTrue("Specified host does not match", hash.isHostMatch(hostName));
        assertFalse("Unexpected host match", hash.isHostMatch(getCurrentTestName()));
    }

    @Test
    public void testCalculateHashValue() throws Exception {
        byte[] expected = hash.getDigestValue();
        byte[] actual = KnownHostHashValue.calculateHashValue(hostName, hash.getDigester(), hash.getSaltValue());
        assertArrayEquals("Mismatched hash value", expected, actual);
    }
}
