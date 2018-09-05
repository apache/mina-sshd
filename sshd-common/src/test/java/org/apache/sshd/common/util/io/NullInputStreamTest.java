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

import java.io.EOFException;
import java.io.IOException;

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
public class NullInputStreamTest extends JUnitTestSupport {
    private static final NullInputStream INSTANCE = new NullInputStream();

    public NullInputStreamTest() {
        super();
    }

    @Test
    public void testReadOneChar() throws IOException {
        assertEquals(-1, INSTANCE.read());
    }

    @Test
    public void testReadFullBuffer() throws IOException {
        assertEquals(-1, INSTANCE.read(new byte[Byte.SIZE]));
    }

    @Test
    public void testReadPartialBuffer() throws IOException {
        byte[] buf = new byte[Byte.SIZE];
        assertEquals(-1, INSTANCE.read(buf, buf.length / 2, (buf.length / 2) - 1));
    }

    @Test
    public void testSkip() throws IOException {
        assertEquals(0L, INSTANCE.skip(Long.SIZE));
    }

    @Test
    public void testAvailable() throws IOException {
        assertEquals(0, INSTANCE.available());
    }

    @Test
    public void testNotAllowedToAccessAfterClose() throws IOException {
        NullInputStream stream = new NullInputStream();
        stream.close();
        assertFalse("Stream not marked as closed", stream.isOpen());

        try {
            int nRead = stream.read();
            fail("Unexpected single byte read: " + nRead);
        } catch (EOFException e) {
            // expected
        }

        byte[] buf = new byte[Byte.SIZE];
        try {
            int nRead = stream.read(buf);
            fail("Unexpected full buffer read: " + nRead);
        } catch (EOFException e) {
            // expected
        }

        try {
            int nRead = stream.read(buf, buf.length / 2, (buf.length / 2) - 1);
            fail("Unexpected partial buffer read: " + nRead);
        } catch (EOFException e) {
            // expected
        }

        try {
            long skip = stream.skip(Long.SIZE);
            fail("Unexpected skip result: " + skip);
        } catch (EOFException e) {
            // expected
        }

        try {
            int nRead = stream.available();
            fail("Unexpected available count: " + nRead);
        } catch (IOException e) {
            // expected
        }
        try {
            stream.reset();
            fail("Unexpected reset success");
        } catch (EOFException e) {
            // expected
        }
    }
}
