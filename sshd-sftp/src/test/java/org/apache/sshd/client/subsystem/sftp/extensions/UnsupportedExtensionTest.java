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

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.AbstractSftpClientTestSupport;
import org.apache.sshd.client.subsystem.sftp.RawSftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
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

    @Test   // see SSHD-890
    public void testUnsupportedExtension() throws IOException {
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (SftpClient sftpClient = createSftpClient(session)) {
                String opcode = getCurrentTestName();
                Buffer buffer = new ByteArrayBuffer(Integer.BYTES + GenericUtils.length(opcode) + Byte.SIZE, false);
                buffer.putString(opcode);

                assertObjectInstanceOf("Not a raw SFTP client", RawSftpClient.class, sftpClient);
                RawSftpClient sftp = (RawSftpClient) sftpClient;
                int cmd = sftp.send(SftpConstants.SSH_FXP_EXTENDED, buffer);
                Buffer responseBuffer = sftp.receive(cmd);

                responseBuffer.getInt();                    // Ignoring length
                int type = responseBuffer.getUByte();
                responseBuffer.getInt();                    // Ignoring message ID
                int substatus = responseBuffer.getInt();

                assertEquals("Type is not STATUS", SftpConstants.SSH_FXP_STATUS, type);
                assertEquals("Sub-Type is not UNSUPPORTED", SftpConstants.SSH_FX_OP_UNSUPPORTED, substatus);
            }
        }
    }
}