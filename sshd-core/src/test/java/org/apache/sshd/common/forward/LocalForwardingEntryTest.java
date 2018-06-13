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

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LocalForwardingEntryTest extends BaseTestSupport {
    public LocalForwardingEntryTest() {
        super();
    }

    @Test   // NOTE: this also checks indirectly SshSocketAddress host comparison case-insensitive
    public void testCaseInsensitiveMatching() {
        LocalForwardingEntry expected = new LocalForwardingEntry(getClass().getSimpleName(), getCurrentTestName(), 7365);
        String hostname = expected.getHostName();
        String alias = expected.getAlias();
        int port = expected.getPort();
        List<LocalForwardingEntry> entries = IntStream.rangeClosed(1, 4)
            .mapToObj(seed -> new LocalForwardingEntry(hostname + "-" + seed, alias + "-" + seed, port + seed))
            .collect(Collectors.toCollection(ArrayList::new));
        entries.add(expected);

        for (String host : new String[] {hostname, alias}) {
            for (int index = 1; index <= 4; index++) {
                Collections.shuffle(entries);

                LocalForwardingEntry actual = LocalForwardingEntry.findMatchingEntry(host, port, entries);
                assertSame("Mismatched result for host=" + host, expected, actual);

                host = shuffleCase(host);
            }
        }
    }
}
