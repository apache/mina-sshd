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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ConfigFileHostEntryResolverTest extends JUnitTestSupport {
    public ConfigFileHostEntryResolverTest() {
        super();
    }

    @Test
    public void testConfigFileReload() throws IOException {
        Path dir = getTempTargetRelativeFile(getClass().getSimpleName());
        AtomicInteger reloadCount = new AtomicInteger();
        ConfigFileHostEntryResolver resolver = new ConfigFileHostEntryResolver(
                assertHierarchyTargetFolderExists(dir).resolve(getCurrentTestName() + ".config.txt")) {
            @Override
            protected List<HostConfigEntry> reloadHostConfigEntries(
                    Path path, String host, int port, String username, String proxyJump)
                    throws IOException {
                reloadCount.incrementAndGet();
                return super.reloadHostConfigEntries(path, host, port, username, proxyJump);
            }
        };
        Path path = resolver.getPath();

        HostConfigEntry expected = new HostConfigEntry(getCurrentTestName(), getCurrentTestName(), 7365, getCurrentTestName());
        testConfigFileReload("Non-existing", path, reloadCount, null, resolver, expected, null);
        testConfigFileReload("Empty", path, reloadCount, Collections.emptyList(), resolver, expected, null);
        testConfigFileReload("Global", path, reloadCount,
                Collections.singletonList(new HostConfigEntry(
                        HostPatternsHolder.ALL_HOSTS_PATTERN, expected.getHost(), expected.getPort(), expected.getUsername())),
                resolver, expected, expected);
        testConfigFileReload("Wildcard", path, reloadCount,
                Arrays.asList(
                        new HostConfigEntry(
                                HostPatternsHolder.ALL_HOSTS_PATTERN,
                                getClass().getSimpleName(),
                                1234,
                                getClass().getSimpleName()),
                        new HostConfigEntry(
                                expected.getHost() + Character.toString(HostPatternsHolder.WILDCARD_PATTERN),
                                expected.getHost(),
                                expected.getPort(),
                                expected.getUsername())),
                resolver, expected, expected);
        testConfigFileReload("Specific", path, reloadCount,
                Arrays.asList(
                        new HostConfigEntry(
                                HostPatternsHolder.ALL_HOSTS_PATTERN,
                                getClass().getSimpleName(),
                                1234,
                                getClass().getSimpleName()),
                        new HostConfigEntry(
                                getClass().getSimpleName() + Character.toString(HostPatternsHolder.WILDCARD_PATTERN),
                                getClass().getSimpleName(),
                                1234,
                                getClass().getSimpleName()),
                        expected),
                resolver, expected, expected);
    }

    private static void testConfigFileReload(
            String phase, Path path, AtomicInteger reloadCount,
            Collection<? extends HostConfigEntry> entries,
            HostConfigEntryResolver resolver,
            HostConfigEntry query,
            HostConfigEntry expected)
            throws IOException {
        if (entries == null) {
            if (Files.exists(path)) {
                Files.delete(path);
            }
        } else {
            HostConfigEntry.writeHostConfigEntries(path, entries, IoUtils.EMPTY_OPEN_OPTIONS);
        }

        reloadCount.set(0);

        for (int index = 1; index < Byte.SIZE; index++) {
            HostConfigEntry actual
                    = resolver.resolveEffectiveHost(query.getHostName(), query.getPort(), null, query.getUsername(), null,
                            null);

            if (entries == null) {
                assertEquals(phase + "[" + index + "]: mismatched reload count", 0, reloadCount.get());
            } else {
                assertEquals(phase + "[" + index + "]: mismatched reload count", 1, reloadCount.get());
            }

            if (expected == null) {
                assertNull(phase + "[" + index + "]: Unexpected success for " + query, actual);
            } else {
                assertNotNull(phase + "[" + index + "]: No result for " + query, actual);
                assertNotSame(phase + "[" + index + "]: No cloned result for " + query, expected, actual);
                assertEquals(phase + "[" + index + "]: Mismatched host for " + query,
                        expected.getHostName(), actual.getHostName());
                assertEquals(phase + "[" + index + "]: Mismatched port for " + query,
                        expected.getPort(), actual.getPort());
                assertEquals(phase + "[" + index + "]: Mismatched user for " + query,
                        expected.getUsername(), actual.getUsername());
            }
        }
    }
}
