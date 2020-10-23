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
public class LocalForwardingEntryCombinedBoundAddressTest extends JUnitTestSupport {
    private final LocalForwardingEntry entry;
    private final SshdSocketAddress expected;

    public LocalForwardingEntryCombinedBoundAddressTest(
                                                        SshdSocketAddress local, SshdSocketAddress bound,
                                                        SshdSocketAddress expected) {
        this.entry = new LocalForwardingEntry(local, bound);
        this.expected = expected;
    }

    @Parameters(name = "local={0}, bound={1}, expected={2}")
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

    @Test
    public void testResolvedValue() {
        assertEquals(expected, entry.getCombinedBoundAddress());
    }

    @Test
    public void testHashCode() {
        assertEquals(expected.hashCode(), entry.hashCode());
    }

    @Test
    public void testSameInstanceReuse() {
        SshdSocketAddress combined = entry.getCombinedBoundAddress();
        SshdSocketAddress local = entry.getLocalAddress();
        SshdSocketAddress bound = entry.getBoundAddress();
        boolean eqLocal = Objects.equals(combined, local);
        boolean eqBound = Objects.equals(combined, bound);
        if (eqLocal) {
            assertSame("Not same local reference", combined, local);
        } else if (eqBound) {
            assertSame("Not same bound reference", combined, bound);
        } else {
            assertNotSame("Unexpected same local reference", combined, local);
            assertNotSame("Unexpected same bound reference", combined, bound);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[entry=" + entry + ", expected=" + expected + "]";
    }
}
