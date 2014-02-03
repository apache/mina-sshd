/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.channel;

import java.util.Arrays;

import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusChannel;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ChannelPipedInputStreamTest extends BaseTest {

    @Test
    public void testAvailable() throws Exception {
        Window window = new Window(new BogusChannel(), null, true, true);
        ChannelPipedInputStream stream = new ChannelPipedInputStream(window);

        byte[] b = "test".getBytes();
        stream.receive(b, 0, b.length);
        assertEquals(b.length, stream.available());

        stream.eof();
        assertEquals(b.length, stream.available());

        final byte[] readBytes = new byte[50];
        assertEquals(b.length, stream.read(readBytes));
        assertStreamEquals(b, readBytes);
        assertEquals(-1, stream.available());
    }

    private void assertStreamEquals(byte[] expected, byte[] read) {
        if (expected.length > read.length) {
            fail("Less bytes than expected: " + Arrays.toString(expected) + " but got: " + Arrays.toString(read));
        } else {
            assertArrayEquals(expected, Arrays.copyOf(read, expected.length));
            for (int i = expected.length; i < read.length; i++) {
                assertEquals('\0', read[i]);
            }
        }
    }

}
