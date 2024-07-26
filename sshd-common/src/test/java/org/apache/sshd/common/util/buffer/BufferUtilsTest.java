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

package org.apache.sshd.common.util.buffer;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class BufferUtilsTest extends JUnitTestSupport {
    public BufferUtilsTest() {
        super();
    }

    @Test
    void hexEncodeDecode() {
        String expValue = getClass().getName() + "#" + getCurrentTestName();
        byte[] expData = expValue.getBytes(StandardCharsets.UTF_8);
        for (char sep : new char[] { BufferUtils.EMPTY_HEX_SEPARATOR, ':' }) {
            String hexData = BufferUtils.toHex(sep, expData);
            byte[] actData = BufferUtils.decodeHex(sep, hexData);
            String actValue = new String(actData, StandardCharsets.UTF_8);
            String sepName = (BufferUtils.EMPTY_HEX_SEPARATOR == sep) ? "EMPTY" : Character.toString(sep);
            outputDebugMessage("Decode(sep=%s) expected=%s, actual=%s", sepName, expValue, actValue);
            assertArrayEquals(expData, actData, "Mismatched result for sep='" + sepName + "'");
        }
    }

    @Test
    void getCompactClone() {
        byte[] expected = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
        final int testOffset = Byte.SIZE / 2;
        byte[] data = new byte[expected.length + 2 * testOffset];
        Random rnd = new Random(System.nanoTime());
        rnd.nextBytes(data);
        System.arraycopy(expected, 0, data, testOffset, expected.length);

        Buffer buf = ByteArrayBuffer.getCompactClone(data, testOffset, expected.length);
        assertEquals(0, buf.rpos(), "Mismatched cloned buffer read position");
        assertEquals(expected.length, buf.available(), "Mismatched cloned buffer available size");

        byte[] actual = buf.array();
        assertNotSame(data, actual, "Original data not cloned");
        assertArrayEquals(expected, actual, "Mismatched cloned contents");
    }
}
