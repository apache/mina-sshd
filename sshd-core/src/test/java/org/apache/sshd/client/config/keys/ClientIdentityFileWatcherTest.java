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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.Utils;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientIdentityFileWatcherTest extends BaseTestSupport {
    public ClientIdentityFileWatcherTest() {
        super();
    }

    @Test
    public void testIdentityReload() throws Exception {
        Path dir = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        final Path idFile = dir.resolve(getCurrentTestName() + ".pem");
        final KeyPair identity = Utils.getFirstKeyPair(createTestHostKeyProvider());
        ClientIdentityLoader loader = new ClientIdentityLoader() {
            @Override
            public KeyPair loadClientIdentity(String location, FilePasswordProvider provider) throws IOException, GeneralSecurityException {
                assertTrue("Invalid location: " + location, isValidLocation(location));
                return identity;
            }

            @Override
            public boolean isValidLocation(String location) throws IOException {
                return Objects.equals(location, toString());
            }

            @Override
            public String toString() {
                return Objects.toString(idFile);
            }
        };

        final AtomicInteger reloadCount = new AtomicInteger(0);
        ClientIdentityProvider idProvider = new ClientIdentityFileWatcher(idFile, loader, FilePasswordProvider.EMPTY, false) {
            @Override
            protected KeyPair reloadClientIdentity(Path path) throws IOException, GeneralSecurityException {
                assertEquals("Mismatched client identity path", idFile, path);
                reloadCount.incrementAndGet();
                return super.reloadClientIdentity(path);
            }
        };
        Files.deleteIfExists(idFile);

        testIdentityReload("Non-existing", reloadCount, idProvider, null, 0);

        touchIdentityFile(idFile);
        for (int index = 1; index < Byte.SIZE; index++) {
            testIdentityReload("Created iteration " + 1, reloadCount, idProvider, identity, 1);
        }

        touchIdentityFile(idFile);
        for (int index = 1; index < Byte.SIZE; index++) {
            testIdentityReload("Modified iteration " + 1, reloadCount, idProvider, identity, 2);
        }
    }

    private static void touchIdentityFile(Path idFile) throws IOException {
        OpenOption[] options = IoUtils.EMPTY_OPEN_OPTIONS;
        if (Files.exists(idFile, IoUtils.EMPTY_LINK_OPTIONS)) {
            options = new OpenOption[]{StandardOpenOption.WRITE, StandardOpenOption.APPEND};
        }

        try (OutputStream out = Files.newOutputStream(idFile, options)) {
            out.write(new Date(System.currentTimeMillis()).toString().getBytes(StandardCharsets.UTF_8));
            out.write('\n');
        }
    }

    private static void testIdentityReload(
            String phase, Number reloadCount, ClientIdentityProvider provider, KeyPair expectedIdentity, int expectedCount)
                throws Exception {
        KeyPair actualIdentity = provider.getClientIdentity();
        assertSame(phase + ": mismatched identity", expectedIdentity, actualIdentity);
        assertEquals(phase + ": mismatched re-load count", expectedCount, reloadCount.intValue());
    }
}
