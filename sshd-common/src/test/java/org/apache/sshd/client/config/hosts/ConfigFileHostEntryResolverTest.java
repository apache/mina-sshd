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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ConfigFileHostEntryResolverTest extends JUnitTestSupport {
    public ConfigFileHostEntryResolverTest() {
        super();
    }

    @Test
    void identityFilePaths() throws IOException {
        final String config = "IdentityFile ~/.ssh/%r.key0\n" //
                              + "Host foo\n" //
                              + "IdentityFile ~/.ssh/%r.key1\n" //
                              + "IdentityFile ~/.ssh/%r.key2\n" //
                              + "Host *\n" //
                              + "IdentityFile ~/.ssh/%r.key3";
        try (InputStream in = new ByteArrayInputStream(config.getBytes(StandardCharsets.US_ASCII))) {
            List<HostConfigEntry> entries = HostConfigEntry.readHostConfigEntries(in, true);
            HostConfigEntryResolver resolver = HostConfigEntry.toHostConfigEntryResolver(entries);
            HostConfigEntry resolved = resolver.resolveEffectiveHost("foo", -1, null, "testuser", null, null);
            assertEquals("foo", resolved.getHostName());
            assertEquals(22, resolved.getPort());
            assertEquals("testuser", resolved.getUsername());
            String prop = resolved.getProperty(HostConfigEntry.IDENTITY_FILE_CONFIG_PROP);
            assertNotNull(prop);
            assertFalse(prop.contains("~"));
            String[] split = prop.split(",");
            assertEquals(4, split.length);
            Collection<String> identities = resolved.getIdentities();
            assertEquals(4, identities.size());
            int i = 0;
            for (String id : identities) {
                assertFalse(id.contains("~"));
                assertTrue(id.endsWith("testuser.key" + i));
                assertEquals(split[i], id);
                i++;
            }
        }
    }

    @Test
    void configFileReload() throws IOException {
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
                                expected.getHost() + Character.toString(HostPatternsHolder.WILDCARD_PATTERN),
                                expected.getHost(),
                                expected.getPort(),
                                expected.getUsername()),
                        new HostConfigEntry(
                                HostPatternsHolder.ALL_HOSTS_PATTERN,
                                getClass().getSimpleName(),
                                1234,
                                getClass().getSimpleName())),
                resolver, expected, expected);
        testConfigFileReload("Specific", path, reloadCount,
                Arrays.asList(
                        new HostConfigEntry(
                                getClass().getSimpleName() + Character.toString(HostPatternsHolder.WILDCARD_PATTERN),
                                getClass().getSimpleName(),
                                1234,
                                getClass().getSimpleName()),
                        expected,
                        new HostConfigEntry(
                                HostPatternsHolder.ALL_HOSTS_PATTERN,
                                getClass().getSimpleName(),
                                1234,
                                getClass().getSimpleName())),
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
            Files.setLastModifiedTime(path, FileTime.from(Instant.now().minusSeconds(4)));
        }

        reloadCount.set(0);

        for (int index = 1; index < Byte.SIZE; index++) {
            HostConfigEntry actual
                    = resolver.resolveEffectiveHost(query.getHostName(), query.getPort(), null, query.getUsername(), null,
                            null);

            if (entries == null) {
                assertEquals(0, reloadCount.get(), phase + "[" + index + "]: mismatched reload count");
            } else {
                assertEquals(1, reloadCount.get(), phase + "[" + index + "]: mismatched reload count");
            }

            if (expected == null) {
                assertNull(actual, phase + "[" + index + "]: Unexpected success for " + query);
            } else {
                assertNotNull(actual, phase + "[" + index + "]: No result for " + query);
                assertNotSame(expected, actual, phase + "[" + index + "]: No cloned result for " + query);
                assertEquals(expected.getHostName(), actual.getHostName(),
                        phase + "[" + index + "]: Mismatched host for " + query);
                assertEquals(expected.getPort(), actual.getPort(), phase + "[" + index + "]: Mismatched port for " + query);
                assertEquals(expected.getUsername(), actual.getUsername(),
                        phase + "[" + index + "]: Mismatched user for " + query);
            }
        }
    }
}
