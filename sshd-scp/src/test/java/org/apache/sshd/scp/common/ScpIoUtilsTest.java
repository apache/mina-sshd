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

package org.apache.sshd.scp.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.scp.common.helpers.ScpIoUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ScpIoUtilsTest extends JUnitTestSupport {

    @Test
    void testProtocolLineLimitExceeded() throws IOException {
        byte[] longLine = new byte[ScpIoUtils.MAX_PROTOCOL_LINE_LENGTH + 2];
        for (int i = 0; i < longLine.length; i++) {
            longLine[i] = 'A';
        }
        ByteArrayInputStream bis = new ByteArrayInputStream(longLine);
        assertThrows(IOException.class, () -> ScpIoUtils.readLine(bis, StandardCharsets.US_ASCII));
        bis.reset();
        longLine[longLine.length - 1] = '\n';
        assertThrows(IOException.class, () -> ScpIoUtils.readLine(bis, StandardCharsets.US_ASCII));
    }

    @Test
    void testProtocolLineLimit() throws IOException {
        byte[] longLine = new byte[ScpIoUtils.MAX_PROTOCOL_LINE_LENGTH + 1];
        for (int i = 0; i < longLine.length; i++) {
            longLine[i] = 'A';
        }
        longLine[longLine.length - 1] = '\n';
        ByteArrayInputStream bis = new ByteArrayInputStream(longLine);
        String s = ScpIoUtils.readLine(bis, StandardCharsets.US_ASCII);
        assertEquals(ScpIoUtils.MAX_PROTOCOL_LINE_LENGTH, s.length());
    }

    @Test
    void testProtocolLineLimitReached() throws IOException {
        byte[] longLine = new byte[ScpIoUtils.MAX_PROTOCOL_LINE_LENGTH];
        for (int i = 0; i < longLine.length; i++) {
            longLine[i] = 'A';
        }
        longLine[longLine.length - 1] = '\n';
        ByteArrayInputStream bis = new ByteArrayInputStream(longLine);
        String s = ScpIoUtils.readLine(bis, StandardCharsets.US_ASCII);
        assertEquals(ScpIoUtils.MAX_PROTOCOL_LINE_LENGTH - 1, s.length());
    }

    @Test
    void testProtocolLineShort() throws IOException {
        byte[] longLine = new byte[ScpIoUtils.MAX_PROTOCOL_LINE_LENGTH];
        for (int i = 0; i < longLine.length; i++) {
            longLine[i] = 'A';
        }
        longLine[42] = '\n';
        ByteArrayInputStream bis = new ByteArrayInputStream(longLine);
        String s = ScpIoUtils.readLine(bis, StandardCharsets.US_ASCII);
        assertEquals(42, s.length());
    }
}
