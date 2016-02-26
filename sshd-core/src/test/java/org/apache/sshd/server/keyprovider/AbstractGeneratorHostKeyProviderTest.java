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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AbstractGeneratorHostKeyProviderTest extends BaseTestSupport {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @SuppressWarnings("synthetic-access")
    @Test
    public void testOverwriteKey() throws Exception {
        File keyPairFile = temporaryFolder.newFile();

        TestProvider provider = new TestProvider(keyPairFile);
        provider.loadKeys();
        assertEquals("Mismatched generate write count", 1, provider.getWriteCount());

        provider = new TestProvider(keyPairFile);
        provider.setOverwriteAllowed(false);
        provider.loadKeys();
        assertEquals("Mismatched load write count", 0, provider.getWriteCount());
    }

    private static final class TestProvider extends AbstractGeneratorHostKeyProvider {
        private final AtomicInteger writes = new AtomicInteger(0);

        private TestProvider(File file) {
            setKeySize(512);
            setPath(file.toPath());
        }

        @Override
        protected KeyPair doReadKeyPair(String resourceKey, InputStream inputStream) throws IOException, GeneralSecurityException {
            return null;
        }

        @Override
        protected void doWriteKeyPair(String resourceKey, KeyPair kp, OutputStream outputStream) throws IOException, GeneralSecurityException {
            writes.incrementAndGet();
        }

        public int getWriteCount() {
            return writes.get();
        }
    }

}