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
package org.apache.sshd.server.keyprovider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class AbstractGeneratorHostKeyProviderTest extends JUnitTestSupport {
    public AbstractGeneratorHostKeyProviderTest() {
        super();
    }

    @Test
    @SuppressWarnings("synthetic-access")
    public void testOverwriteKey() throws Exception {
        Path tempDir = assertHierarchyTargetFolderExists(getTempTargetFolder());
        Path keyPairFile = tempDir.resolve(getCurrentTestName() + ".key");
        Files.deleteIfExists(keyPairFile);

        TestProvider provider = new TestProvider(keyPairFile);
        provider.loadKeys(null);
        assertEquals("Mismatched generate write count", 1, provider.getWriteCount());

        provider = new TestProvider(keyPairFile);
        provider.setOverwriteAllowed(false);
        provider.loadKeys(null);
        assertEquals("Mismatched load write count", 0, provider.getWriteCount());
    }

    private static final class TestProvider extends AbstractGeneratorHostKeyProvider {
        private final AtomicInteger writes = new AtomicInteger(0);

        private TestProvider(Path file) {
            setPath(file);
        }

        @Override
        protected Iterable<KeyPair> doReadKeyPairs(
                SessionContext session, NamedResource resourceKey, InputStream inputStream)
                throws IOException, GeneralSecurityException {
            return null;
        }

        @Override
        protected void doWriteKeyPair(NamedResource resourceKey, KeyPair kp, OutputStream outputStream)
                throws IOException, GeneralSecurityException {
            writes.incrementAndGet();
        }

        public int getWriteCount() {
            return writes.get();
        }
    }
}
