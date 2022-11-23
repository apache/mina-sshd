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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link SftpStatus}.
 */
@Category(NoIoTestCase.class)
public class SftpStatusTest {

    public SftpStatusTest() {
        super();
    }

    @Test
    public void testOkStatus() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_OK);
        buffer.putString("An error message");
        buffer.putString("en");
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals("Unexpected status code", SftpConstants.SSH_FX_OK, status.getStatusCode());
        assertEquals("Unexpected error message", "An error message", status.getMessage());
        assertEquals("Unexpected language tag", "en", status.getLanguage());
        assertTrue("Status should be OK", status.isOk());
    }

    @Test
    public void testOkStatusNoMessage() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_OK);
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals("Unexpected status code", SftpConstants.SSH_FX_OK, status.getStatusCode());
        assertNull("Unexpected error message", status.getMessage());
        assertNull("Unexpected language tag", status.getLanguage());
        assertTrue("Status should be OK", status.isOk());
    }

    @Test
    public void testNokStatus() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_EOF);
        buffer.putString("An error message");
        buffer.putString("en");
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals("Unexpected status code", SftpConstants.SSH_FX_EOF, status.getStatusCode());
        assertEquals("Unexpected error message", "An error message", status.getMessage());
        assertEquals("Unexpected language tag", "en", status.getLanguage());
        assertFalse("Status should be OK", status.isOk());
    }

    @Test
    public void testNokStatusNoMessage() {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(SftpConstants.SSH_FX_FAILURE);
        SftpStatus status = SftpStatus.parse(buffer);
        assertEquals("Unexpected status code", SftpConstants.SSH_FX_FAILURE, status.getStatusCode());
        assertNull("Unexpected error message", status.getMessage());
        assertNull("Unexpected language tag", status.getLanguage());
        assertFalse("Status should be OK", status.isOk());
    }
}
