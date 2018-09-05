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

package org.apache.sshd.common.util.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

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
public class LimitInputStreamTest extends JUnitTestSupport {
    public LimitInputStreamTest() {
        super();
    }

    @Test
    public void testReadLimit() throws IOException {
        Path targetPath = detectTargetFolder();
        Path rootFolder = assertHierarchyTargetFolderExists(targetPath.resolve(getClass().getSimpleName()));
        Path inputFile = rootFolder.resolve(getCurrentTestName() + ".bin");
        byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        Files.write(inputFile, data);

        try (InputStream in = Files.newInputStream(inputFile)) {
            int maxLen = data.length / 2;
            byte[] expected = new byte[maxLen];
            System.arraycopy(data, 0, expected, 0, expected.length);

            byte[] actual = new byte[expected.length];
            try (LimitInputStream limited = new LimitInputStream(in, expected.length)) {
                assertTrue("Limited stream not marked as open", limited.isOpen());
                assertEquals("Mismatched initial available data size", expected.length, limited.available());

                int readLen = limited.read(actual);
                assertEquals("Incomplete actual data read", actual.length, readLen);
                assertArrayEquals("Mismatched read data", expected, actual);
                assertEquals("Mismatched remaining available data size", 0, limited.available());

                readLen = limited.read();
                assertTrue("Unexpected success to read one more byte: " + readLen, readLen < 0);

                readLen = limited.read(actual);
                assertTrue("Unexpected success to read extra buffer: " + readLen, readLen < 0);

                limited.close();
                assertFalse("Limited stream still marked as open", limited.isOpen());

                try {
                    readLen = limited.read();
                    fail("Unexpected one byte read success after close");
                } catch (IOException e) {
                    // expected
                }

                try {
                    readLen = limited.read(actual);
                    fail("Unexpected buffer read success after close: " + readLen);
                } catch (IOException e) {
                    // expected
                }

                try {
                    readLen = limited.read(actual);
                    fail("Unexpected buffer read success after close: " + readLen);
                } catch (IOException e) {
                    // expected
                }

                try {
                    readLen = (int) limited.skip(Byte.SIZE);
                    fail("Unexpected skip success after close: " + readLen);
                } catch (IOException e) {
                    // expected
                }

                try {
                    readLen = limited.available();
                    fail("Unexpected available success after close: " + readLen);
                } catch (IOException e) {
                    // expected
                }
            }

            // make sure underlying stream not closed
            int readLen = in.read(actual);
            assertEquals("Incomplete extra data read", Math.min(actual.length, data.length - expected.length), readLen);
        }
    }
}
