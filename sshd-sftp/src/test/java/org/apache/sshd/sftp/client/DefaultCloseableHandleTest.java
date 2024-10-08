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

package org.apache.sshd.sftp.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.Handle;
import org.apache.sshd.sftp.client.impl.DefaultCloseableHandle;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class DefaultCloseableHandleTest extends JUnitTestSupport {
    public DefaultCloseableHandleTest() {
        super();
    }

    @Test
    void channelBehavior() throws IOException {
        final byte[] id = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
        SftpClient client = Mockito.mock(SftpClient.class);
        Mockito.doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            Handle handle = (Handle) args[0];
            assertArrayEquals(id, handle.getIdentifier(), "Mismatched closing handle");
            return null;
        }).when(client).close(ArgumentMatchers.any(Handle.class));

        CloseableHandle handle = new DefaultCloseableHandle(client, getCurrentTestName(), id);
        try {
            assertTrue(handle.isOpen(), "Handle not initially open");
        } finally {
            handle.close();
        }
        assertFalse(handle.isOpen(), "Handle not marked as closed");
        // make sure close was called
        Mockito.verify(client).close(handle);
    }

    @Test
    void closeIdempotent() throws IOException {
        SftpClient client = Mockito.mock(SftpClient.class);
        final AtomicBoolean closeCalled = new AtomicBoolean(false);
        Mockito.doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assertFalse(closeCalled.getAndSet(true), "Close already called on handle=" + args[0]);
            return null;
        }).when(client).close(ArgumentMatchers.any(Handle.class));

        CloseableHandle handle = new DefaultCloseableHandle(
                client, getCurrentTestName(), getCurrentTestName().getBytes(StandardCharsets.UTF_8));
        for (int index = 0; index < Byte.SIZE; index++) {
            handle.close();
        }

        assertTrue(closeCalled.get(), "Close method not called");
    }
}
