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

import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class EmptyInputStreamTest extends JUnitTestSupport {
    public EmptyInputStreamTest() {
        super();
    }

    @Test
    void emptyInputStream() throws IOException {
        try (EmptyInputStream in = new EmptyInputStream()) {
            testEmptyInputStream(in, false);
        }
    }

    @Test
    void closeableEmptyInputStream() throws IOException {
        try (EmptyInputStream in = new CloseableEmptyInputStream()) {
            testEmptyInputStream(in, true);
        }
    }

    private void testEmptyInputStream(InputStream in, boolean failAfterClose) throws IOException {
        testEmptyInputStream("open", in, false);
        in.close();
        testEmptyInputStream("closed", in, failAfterClose);
    }

    private void testEmptyInputStream(String message, InputStream in, boolean errorExpected) {
        assertFalse(in.markSupported(), message + ": unexpected markSupported()");
        assertThrows(UnsupportedOperationException.class, () -> in.mark(Long.SIZE), message + ": unexpected mark success");

        try {
            int len = in.available();
            assertFalse(errorExpected, message + ": Unexpected success in available(): " + len);
            assertEquals(0, len, message + ": Mismatched available() result");
        } catch (IOException e) {
            assertTrue(errorExpected, message + ": Unexpected error on available(): " + e.getMessage());
        }

        try {
            int data = in.read();
            assertFalse(errorExpected, message + ": Unexpected success in read(): " + data);
            assertEquals(-1, data, message + ": Mismatched read() result");
        } catch (IOException e) {
            assertTrue(errorExpected, message + ": Unexpected error on read(): " + e.getMessage());
        }

        byte[] bytes = new byte[Byte.SIZE];
        try {
            int len = in.read(bytes);
            assertFalse(errorExpected, message + ": Unexpected success in read([]): " + BufferUtils.toHex(':', bytes));
            assertEquals(-1, len, message + ": Mismatched read([]) result");
        } catch (IOException e) {
            assertTrue(errorExpected, message + ": Unexpected error on read([]): " + e.getMessage());
        }

        try {
            int len = in.read(bytes, 0, bytes.length);
            assertFalse(errorExpected, message + ": Unexpected success in read([],int,int): " + BufferUtils.toHex(':', bytes));
            assertEquals(-1, len, message + ": Mismatched read([],int,int) result");
        } catch (IOException e) {
            assertTrue(errorExpected, message + ": Unexpected error on read([],int,int): " + e.getMessage());
        }

        try {
            long len = in.skip(Byte.MAX_VALUE);
            assertFalse(errorExpected, message + ": Unexpected success in skip(): " + len);
            assertEquals(0L, len, message + ": Mismatched skip() result");
        } catch (IOException e) {
            assertTrue(errorExpected, message + ": Unexpected error on skip(): " + e.getMessage());
        }

        try {
            in.reset();
            assertFalse(errorExpected, message + ": Unexpected success in reset()");
        } catch (IOException e) {
            assertTrue(errorExpected, message + ": Unexpected error on reset(): " + e.getMessage());
        }
    }
}
