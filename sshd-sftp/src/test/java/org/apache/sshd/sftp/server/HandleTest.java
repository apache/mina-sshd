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
package org.apache.sshd.sftp.server;

import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertEquals;

@Category({ NoIoTestCase.class })
public class HandleTest {

    public HandleTest() {
        super();
    }

    private void roundtrip(long x) {
        byte[] buf = new byte[Integer.BYTES];
        BufferUtils.putUInt(x, buf);
        String s = new String(buf, StandardCharsets.ISO_8859_1);
        int h = s.hashCode();
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(s, StandardCharsets.ISO_8859_1);
        String t = buffer.getString(StandardCharsets.ISO_8859_1);
        assertEquals("Hash for " + x + " different", h, t.hashCode());
        assertEquals("String for " + x + " different", s, t);
        byte[] b = t.getBytes(StandardCharsets.ISO_8859_1);
        long j = BufferUtils.getUInt(b);
        assertEquals("Values different", x, j);
    }

    @Test
    public void testIntegerStringRoundtrip() {
        final int limit = 100_000;
        for (long i = 0; i <= limit; i++) {
            roundtrip(i);
        }
        for (long i = Integer.MAX_VALUE; i >= Integer.MAX_VALUE - limit; i--) {
            roundtrip(i);
        }
        roundtrip(0x01020304);
        roundtrip(0x77ccdd01);
    }
}
