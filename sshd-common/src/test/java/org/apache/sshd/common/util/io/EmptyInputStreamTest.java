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

import org.apache.sshd.common.util.buffer.BufferUtils;
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
public class EmptyInputStreamTest extends JUnitTestSupport {
    public EmptyInputStreamTest() {
        super();
    }

    @Test
    public void testEmptyInputStream() throws IOException {
        try (EmptyInputStream in = new EmptyInputStream()) {
            testEmptyInputStream(in, false);
        }
    }

    @Test
    public void testCloseableEmptyInputStream() throws IOException {
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
        assertFalse(message + ": unexpected markSupported()", in.markSupported());
        try {
            in.mark(Long.SIZE);
            fail(message + ": unexpected mark success");
        } catch (UnsupportedOperationException e) {
            // expected
        }

        try {
            int len = in.available();
            assertFalse(message + ": Unexpected success in available(): " + len, errorExpected);
            assertEquals(message + ": Mismatched available() result", 0, len);
        } catch (IOException e) {
            assertTrue(message + ": Unexpected error on available(): " + e.getMessage(), errorExpected);
        }

        try {
            int data = in.read();
            assertFalse(message + ": Unexpected success in read(): " + data, errorExpected);
            assertEquals(message + ": Mismatched read() result", -1, data);
        } catch (IOException e) {
            assertTrue(message + ": Unexpected error on read(): " + e.getMessage(), errorExpected);
        }

        byte[] bytes = new byte[Byte.SIZE];
        try {
            int len = in.read(bytes);
            assertFalse(message + ": Unexpected success in read([]): " + BufferUtils.toHex(':', bytes), errorExpected);
            assertEquals(message + ": Mismatched read([]) result", -1, len);
        } catch (IOException e) {
            assertTrue(message + ": Unexpected error on read([]): " + e.getMessage(), errorExpected);
        }

        try {
            int len = in.read(bytes, 0, bytes.length);
            assertFalse(message + ": Unexpected success in read([],int,int): " + BufferUtils.toHex(':', bytes), errorExpected);
            assertEquals(message + ": Mismatched read([],int,int) result", -1, len);
        } catch (IOException e) {
            assertTrue(message + ": Unexpected error on read([],int,int): " + e.getMessage(), errorExpected);
        }

        try {
            long len = in.skip(Byte.MAX_VALUE);
            assertFalse(message + ": Unexpected success in skip(): " + len, errorExpected);
            assertEquals(message + ": Mismatched skip() result", 0L, len);
        } catch (IOException e) {
            assertTrue(message + ": Unexpected error on skip(): " + e.getMessage(), errorExpected);
        }

        try {
            in.reset();
            assertFalse(message + ": Unexpected success in reset()", errorExpected);
        } catch (IOException e) {
            assertTrue(message + ": Unexpected error on reset(): " + e.getMessage(), errorExpected);
        }
    }
}
