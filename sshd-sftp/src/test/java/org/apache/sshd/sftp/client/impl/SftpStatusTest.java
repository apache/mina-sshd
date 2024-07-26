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
package org.apache.sshd.sftp.client.impl;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.sftp.common.SftpConstants;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link SftpStatus}.
 */
@Tag("NoIoTestCase")
public class SftpStatusTest {

    public SftpStatusTest() {
        super();
    }

    @Test
    void okStatus() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_OK);
        buffer.putString("An error message");
        buffer.putString("en");
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals(SftpConstants.SSH_FX_OK, status.getStatusCode(), "Unexpected status code");
        assertEquals("An error message", status.getMessage(), "Unexpected error message");
        assertEquals("en", status.getLanguage(), "Unexpected language tag");
        assertTrue(status.isOk(), "Status should be OK");
    }

    @Test
    void okStatusNoMessage() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_OK);
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals(SftpConstants.SSH_FX_OK, status.getStatusCode(), "Unexpected status code");
        assertNull(status.getMessage(), "Unexpected error message");
        assertNull(status.getLanguage(), "Unexpected language tag");
        assertTrue(status.isOk(), "Status should be OK");
    }

    @Test
    void nokStatus() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_EOF);
        buffer.putString("An error message");
        buffer.putString("en");
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals(SftpConstants.SSH_FX_EOF, status.getStatusCode(), "Unexpected status code");
        assertEquals("An error message", status.getMessage(), "Unexpected error message");
        assertEquals("en", status.getLanguage(), "Unexpected language tag");
        assertFalse(status.isOk(), "Status should be OK");
    }

    @Test
    void nokStatusNoMessage() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_FAILURE);
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals(SftpConstants.SSH_FX_FAILURE, status.getStatusCode(), "Unexpected status code");
        assertNull(status.getMessage(), "Unexpected error message");
        assertNull(status.getLanguage(), "Unexpected language tag");
        assertFalse(status.isOk(), "Status should be OK");
    }
}
