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

package org.apache.sshd.client.subsystem.sftp.extensions;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.AbstractSftpClientTestSupport;
import org.apache.sshd.client.subsystem.sftp.impl.DefaultSftpClient;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UnsupportedExtensionTest extends AbstractSftpClientTestSupport {

    public UnsupportedExtensionTest() throws IOException {
        super();
    }

    @Test
    public void testUnsupportedExtension() throws IOException {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (DefaultSftpClient sftp = (DefaultSftpClient) createSftpClient(session)) {
                    String opcode = "UnsupportedExtension";
                    Buffer buffer = new ByteArrayBuffer(Integer.BYTES + GenericUtils.length(opcode) + Byte.SIZE, false);
                    buffer.putString(opcode);

                    Buffer responseBuffer = sftp.receive(sftp.send(SftpConstants.SSH_FXP_EXTENDED, buffer));

                    responseBuffer.getInt();                    // Ignoring length
                    int type = responseBuffer.getUByte();
                    responseBuffer.getInt();                    // Ignoring message ID
                    int substatus = responseBuffer.getInt();

                    assertEquals("Type is not STATUS", SftpConstants.SSH_FXP_STATUS, type);
                    assertEquals("Sub Type is not UNSUPPORTED", SftpConstants.SSH_FX_OP_UNSUPPORTED, substatus);
                }
            }
        }

    }

}
