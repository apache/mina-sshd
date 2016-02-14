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

package org.apache.sshd.common.util;

import java.nio.charset.StandardCharsets;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Base64Test extends BaseTestSupport {
    public Base64Test() {
        super();
    }

    @Test
    public void testDiscardWhitespaceNullOrEmptyData() {
        assertSame("Mismatched result for null data", GenericUtils.EMPTY_BYTE_ARRAY, Base64.discardWhitespace(null));
        assertSame("Mismatched result for empty data", GenericUtils.EMPTY_BYTE_ARRAY, Base64.discardWhitespace(new byte[0]));
    }

    @Test
    public void testDiscardWhitespaceOnNonWhitespace() {
        byte[] expected = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
        byte[] actual = Base64.discardWhitespace(expected);
        assertSame("Mismatched result", expected, actual);
    }

    @Test
    public void testDiscardWhitespaceOnExistingWhitespace() {
        String expected = getCurrentTestName();
        StringBuilder sb = new StringBuilder(expected.length() * 2);
        for (int index = 0; index < expected.length(); index++) {
            sb.append(" \t\r\n".charAt(index % 4)).append(expected.charAt(index));
        }

        byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] result = Base64.discardWhitespace(data);
        assertEquals("Mismatched cleaned result", expected, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testBasicEncodeDecode() {
        String expected = getCurrentTestName();
        String b64 = Base64.encodeToString(expected.getBytes(StandardCharsets.UTF_8));
        byte[] decoded = Base64.decodeBase64(b64.getBytes(StandardCharsets.UTF_8));
        String actual = new String(decoded, StandardCharsets.UTF_8);
        assertEquals("Mismatched decoded result for " + b64, expected, actual);

    }
}
