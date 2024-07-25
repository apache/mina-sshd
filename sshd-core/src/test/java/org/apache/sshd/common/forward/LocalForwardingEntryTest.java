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
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class LocalForwardingEntryTest extends BaseTestSupport {
    public LocalForwardingEntryTest() {
        super();
    }

    // NOTE: this also checks indirectly SshSocketAddress host comparison case-insensitive
    @Test
    void caseInsensitiveMatching() {
        SshdSocketAddress local = new SshdSocketAddress(getClass().getSimpleName(), 0);
        SshdSocketAddress bound = new SshdSocketAddress(getCurrentTestName(), 7365);
        LocalForwardingEntry expected = new LocalForwardingEntry(local, bound);
        String hostname = local.getHostName();
        String alias = bound.getHostName();
        int port = bound.getPort();
        List<LocalForwardingEntry> entries = IntStream.rangeClosed(1, 4)
                .mapToObj(seed -> new LocalForwardingEntry(
                        new SshdSocketAddress(hostname + "-" + seed, 0),
                        new SshdSocketAddress(alias + "-" + seed, port + seed)))
                .collect(Collectors.toCollection(ArrayList::new));
        entries.add(expected);

        for (String host : new String[] { hostname, alias }) {
            for (int index = 1; index <= 4; index++) {
                Collections.shuffle(entries);

                LocalForwardingEntry actual = LocalForwardingEntry.findMatchingEntry(host, port, entries);
                assertSame(expected, actual, "Mismatched result for host=" + host);

                host = shuffleCase(host);
            }
        }
    }

    @Test
    void singleWildcardMatching() {
        SshdSocketAddress address = new SshdSocketAddress(getCurrentTestName(), 7365);
        LocalForwardingEntry expected = new LocalForwardingEntry(address, address);
        int port = address.getPort();
        List<LocalForwardingEntry> entries = IntStream.rangeClosed(1, 4)
                .mapToObj(seed -> {
                    String hostname = address.getHostName();
                    SshdSocketAddress other = new SshdSocketAddress(hostname + "-" + seed, port + seed);
                    return new LocalForwardingEntry(other, other);
                }).collect(Collectors.toCollection(ArrayList::new));
        entries.add(expected);

        for (String host : new String[] {
                SshdSocketAddress.IPV4_ANYADDR,
                SshdSocketAddress.IPV6_LONG_ANY_ADDRESS,
                SshdSocketAddress.IPV6_SHORT_ANY_ADDRESS
        }) {
            LocalForwardingEntry actual = LocalForwardingEntry.findMatchingEntry(host, port, entries);
            assertSame(expected, actual, "Host=" + host);
        }
    }

    @Test
    void loopbackMatching() {
        int port = 7365;
        List<LocalForwardingEntry> entries = IntStream.rangeClosed(1, 4)
                .mapToObj(seed -> {
                    String hostname = getCurrentTestName();
                    SshdSocketAddress other = new SshdSocketAddress(hostname + "-" + seed, port + seed);
                    return new LocalForwardingEntry(other, other);
                }).collect(Collectors.toCollection(ArrayList::new));
        int numEntries = entries.size();
        for (String host : new String[] {
                SshdSocketAddress.LOCALHOST_IPV4,
                SshdSocketAddress.IPV6_LONG_LOCALHOST,
                SshdSocketAddress.IPV6_SHORT_LOCALHOST
        }) {
            SshdSocketAddress bound = new SshdSocketAddress(host, port);
            LocalForwardingEntry expected = new LocalForwardingEntry(bound, bound);
            entries.add(expected);

            LocalForwardingEntry actual
                    = LocalForwardingEntry.findMatchingEntry(SshdSocketAddress.LOCALHOST_NAME, port, entries);
            entries.remove(numEntries);
            assertSame(expected, actual, "Host=" + host);
        }
    }

    @Test
    void multipleWildcardCandidates() {
        int port = 7365;
        List<LocalForwardingEntry> entries = IntStream.rangeClosed(1, 4)
                .mapToObj(seed -> {
                    String hostname = getCurrentTestName();
                    SshdSocketAddress other = new SshdSocketAddress(hostname + "-" + seed, port + seed);
                    return new LocalForwardingEntry(other, other);
                }).collect(Collectors.toCollection(ArrayList::new));
        for (int index = 0; index < 4; index++) {
            SshdSocketAddress duplicate = new SshdSocketAddress(getClass().getSimpleName() + "-" + index, port);
            entries.add(new LocalForwardingEntry(duplicate, duplicate));
        }

        for (String host : new String[] {
                SshdSocketAddress.IPV4_ANYADDR,
                SshdSocketAddress.IPV6_LONG_ANY_ADDRESS,
                SshdSocketAddress.IPV6_SHORT_ANY_ADDRESS
        }) {
            try {
                LocalForwardingEntry actual = LocalForwardingEntry.findMatchingEntry(host, port, entries);
                fail("Unexpected success for host=" + host + ": " + actual);
            } catch (IllegalStateException e) {
                String msg = e.getMessage();
                assertTrue(msg.startsWith("Multiple candidate matches for " + host + "@" + port + ":"),
                        "Bad exception message: " + msg);
            }
        }
    }
}
