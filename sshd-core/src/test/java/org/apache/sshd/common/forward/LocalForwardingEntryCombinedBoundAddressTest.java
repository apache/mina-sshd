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

package org.apache.sshd.common.forward;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class LocalForwardingEntryCombinedBoundAddressTest extends JUnitTestSupport {
    private LocalForwardingEntry entry;
    private SshdSocketAddress expected;

    public void initLocalForwardingEntryCombinedBoundAddressTest(
            SshdSocketAddress local, SshdSocketAddress bound,
            SshdSocketAddress expected) {
        this.entry = new LocalForwardingEntry(local, bound);
        this.expected = expected;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                SshdSocketAddress bound = new SshdSocketAddress("10.10.10.10", 7365);
                addTestCase(bound, bound, bound);

                SshdSocketAddress specificLocal = new SshdSocketAddress("specificLocal", bound.getPort());
                addTestCase(specificLocal, bound, specificLocal);

                SshdSocketAddress noLocalPort = new SshdSocketAddress(specificLocal.getHostName(), 0);
                addTestCase(noLocalPort, bound, new SshdSocketAddress(specificLocal.getHostName(), bound.getPort()));

                for (String address : new String[] {
                        "", SshdSocketAddress.IPV4_ANYADDR,
                        SshdSocketAddress.IPV6_LONG_ANY_ADDRESS,
                        SshdSocketAddress.IPV6_SHORT_ANY_ADDRESS
                }) {
                    SshdSocketAddress wildcard = new SshdSocketAddress(address, bound.getPort());
                    addTestCase(wildcard, bound, bound);
                }
            }

            private void addTestCase(
                    SshdSocketAddress local, SshdSocketAddress bound, SshdSocketAddress expected) {
                add(new Object[] { local, bound, expected });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "local={0}, bound={1}, expected={2}")
    public void resolvedValue(SshdSocketAddress local, SshdSocketAddress bound, SshdSocketAddress expected) {
        initLocalForwardingEntryCombinedBoundAddressTest(local, bound, expected);
        assertEquals(expected, entry.getCombinedBoundAddress());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "local={0}, bound={1}, expected={2}")
    public void testHashCode(SshdSocketAddress local, SshdSocketAddress bound, SshdSocketAddress expected) {
        initLocalForwardingEntryCombinedBoundAddressTest(local, bound, expected);
        assertEquals(expected.hashCode(), entry.hashCode());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "local={0}, bound={1}, expected={2}")
    public void sameInstanceReuse(SshdSocketAddress local, SshdSocketAddress bound, SshdSocketAddress expected) {
        initLocalForwardingEntryCombinedBoundAddressTest(local, bound, expected);
        SshdSocketAddress combined = entry.getCombinedBoundAddress();
        boolean eqLocal = Objects.equals(combined, local);
        boolean eqBound = Objects.equals(combined, bound);
        if (eqLocal) {
            assertSame(combined, local, "Not same local reference");
        } else if (eqBound) {
            assertSame(combined, bound, "Not same bound reference");
        } else {
            assertNotSame(combined, local, "Unexpected same local reference");
            assertNotSame(combined, bound, "Unexpected same bound reference");
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[entry=" + entry + ", expected=" + expected + "]";
    }
}
