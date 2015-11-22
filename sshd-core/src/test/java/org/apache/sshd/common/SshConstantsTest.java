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

package org.apache.sshd.common;

import java.lang.reflect.Field;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SshConstantsTest extends BaseTestSupport {
    public SshConstantsTest() {
        super();
    }

    @Test
    public void testGetDisconnectReason() {
        for (int reason = SshConstants.SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT; reason <= SshConstants.SSH2_DISCONNECT_ILLEGAL_USER_NAME; reason++) {
            String name = SshConstants.getDisconnectReasonName(reason);
            assertTrue("Mismatched name for reason=" + reason + ": " + name, name.startsWith("SSH2_DISCONNECT_"));
        }
    }

    @Test
    public void testGetOpenErrorName() {
        for (int code = SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED; code <= SshConstants.SSH_OPEN_RESOURCE_SHORTAGE; code++) {
            String name = SshConstants.getOpenErrorCodeName(code);
            assertTrue("Mismatched name for code=" + code + ": " + name, name.startsWith("SSH_OPEN_"));
        }
    }

    @Test
    public void testAmbiguousOpcodes() throws Exception {
        for (String name : SshConstants.AMBIGUOUS_OPCODES) {
            Field f = SshConstants.class.getField(name);
            int cmd = f.getByte(null) & 0xFF;
            assertEquals("Mismatched mnemonic for " + name, Integer.toString(cmd), SshConstants.getCommandMessageName(cmd));
        }
    }
}
