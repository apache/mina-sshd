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

package org.apache.sshd.common.util.io.input;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class LimitInputStreamTest extends JUnitTestSupport {
    public LimitInputStreamTest() {
        super();
    }

    @Test
    void readLimit() throws IOException {
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
                assertTrue(limited.isOpen(), "Limited stream not marked as open");
                assertEquals(expected.length, limited.available(), "Mismatched initial available data size");

                int readLen = limited.read(actual);
                assertEquals(actual.length, readLen, "Incomplete actual data read");
                assertArrayEquals(expected, actual, "Mismatched read data");
                assertEquals(0, limited.available(), "Mismatched remaining available data size");

                readLen = limited.read();
                assertTrue(readLen < 0, "Unexpected success to read one more byte: " + readLen);

                readLen = limited.read(actual);
                assertTrue(readLen < 0, "Unexpected success to read extra buffer: " + readLen);

                limited.close();
                assertFalse(limited.isOpen(), "Limited stream still marked as open");

                assertThrows(IOException.class, limited::read, "Unexpected one byte read success after close");

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
            assertEquals(Math.min(actual.length, data.length - expected.length), readLen, "Incomplete extra data read");
        }
    }
}
