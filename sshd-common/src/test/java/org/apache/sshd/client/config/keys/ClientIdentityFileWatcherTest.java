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

package org.apache.sshd.client.config.keys;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ClientIdentityFileWatcherTest extends JUnitTestSupport {
    public ClientIdentityFileWatcherTest() {
        super();
    }

    @Test
    void identityReload() throws Exception {
        Path dir = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        Path idFile = dir.resolve(getCurrentTestName() + ".pem");
        KeyPair identity = CommonTestSupportUtils.getFirstKeyPair(createTestHostKeyProvider());
        ClientIdentityLoader loader = new ClientIdentityLoader() {
            @Override
            public Iterable<KeyPair> loadClientIdentities(
                    SessionContext session, NamedResource location, FilePasswordProvider provider)
                    throws IOException, GeneralSecurityException {
                assertTrue(isValidLocation(location), "Invalid location: " + location);
                return Collections.singletonList(identity);
            }

            @Override
            public boolean isValidLocation(NamedResource location) throws IOException {
                return Objects.equals(location.getName(), toString());
            }

            @Override
            public String toString() {
                return Objects.toString(idFile);
            }
        };

        AtomicInteger reloadCount = new AtomicInteger(0);
        ClientIdentityProvider idProvider = new ClientIdentityFileWatcher(idFile, loader, FilePasswordProvider.EMPTY, false) {
            @Override
            protected Iterable<KeyPair> reloadClientIdentities(SessionContext session, Path path)
                    throws IOException, GeneralSecurityException {
                assertEquals("Mismatched client identity path", idFile, path);
                reloadCount.incrementAndGet();
                return super.reloadClientIdentities(session, path);
            }
        };
        Files.deleteIfExists(idFile);

        testIdentityReload("Non-existing", reloadCount, idProvider, null, 0);

        touchIdentityFile(idFile, Instant.now().minusSeconds(6));
        for (int index = 1; index < Byte.SIZE; index++) {
            testIdentityReload("Created iteration " + 1, reloadCount, idProvider, identity, 1);
        }

        touchIdentityFile(idFile, Instant.now().minusSeconds(4));
        for (int index = 1; index < Byte.SIZE; index++) {
            testIdentityReload("Modified iteration " + 1, reloadCount, idProvider, identity, 2);
        }
    }

    private static void touchIdentityFile(Path idFile, Instant fileTime) throws IOException {
        OpenOption[] options = IoUtils.EMPTY_OPEN_OPTIONS;
        if (Files.exists(idFile, IoUtils.EMPTY_LINK_OPTIONS)) {
            options = new OpenOption[] { StandardOpenOption.WRITE, StandardOpenOption.APPEND };
        }

        try (OutputStream out = Files.newOutputStream(idFile, options)) {
            out.write(new Date(System.currentTimeMillis()).toString().getBytes(StandardCharsets.UTF_8));
            out.write('\n');
        }
        Files.setLastModifiedTime(idFile, FileTime.from(fileTime));
    }

    private static void testIdentityReload(
            String phase, Number reloadCount, ClientIdentityProvider provider, KeyPair expectedIdentity, int expectedCount)
            throws Exception {
        Iterable<KeyPair> ids = provider.getClientIdentities(null);
        KeyPair actualIdentity = GenericUtils.head(ids);
        assertSame(expectedIdentity, actualIdentity, phase + ": mismatched identity");
        assertEquals(expectedCount, reloadCount.intValue(), phase + ": mismatched re-load count");
    }
}
