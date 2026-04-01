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

package org.apache.sshd.common.compression;

import java.io.IOException;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
class CompresssionZlibTest extends JUnitTestSupport {

    CompresssionZlibTest() {
        super();
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 32, 255, 256, 257, 258, 259, 260, 261, 300 })
    void maxSize(int size) throws IOException {
        boolean expectSuccess = size <= 256;
        byte[] data = new byte[size * 1024];
        Compression comp = BuiltinCompressions.zlib.create();
        comp.init(Compression.Type.Deflater, 9);
        Buffer buf = new ByteArrayBuffer();
        buf.putRawBytes(data);
        assertEquals(data.length, buf.available());
        comp.compress(buf);
        assertTrue(buf.available() < data.length);
        assertTrue(buf.available() <= 256 * 1024);

        Compression decompress = BuiltinCompressions.zlib.create();
        decompress.init(Compression.Type.Inflater, 9);
        Buffer dec = new ByteArrayBuffer();
        if (expectSuccess) {
            decompress.uncompress(buf, dec);
            assertEquals(data.length, dec.available());
            assertArrayEquals(data, dec.getCompactData());
        } else {
            assertThrows(SshException.class, () -> {
                decompress.uncompress(buf, dec);
            });
            assertTrue(dec.available() <= 256 * 1024);
        }
    }

}
