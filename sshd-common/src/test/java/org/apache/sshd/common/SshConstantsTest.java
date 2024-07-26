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

import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SshConstantsTest extends JUnitTestSupport {
    public SshConstantsTest() {
        super();
    }

    @Test
    void getDisconnectReason() {
        for (int reason = SshConstants.SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT;
             reason <= SshConstants.SSH2_DISCONNECT_ILLEGAL_USER_NAME;
             reason++) {
            String name = SshConstants.getDisconnectReasonName(reason);
            assertTrue(name.startsWith("SSH2_DISCONNECT_"), "Mismatched name for reason=" + reason + ": " + name);
        }
    }

    @Test
    void getOpenErrorName() {
        for (int code = SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;
             code <= SshConstants.SSH_OPEN_RESOURCE_SHORTAGE;
             code++) {
            String name = SshConstants.getOpenErrorCodeName(code);
            assertTrue(name.startsWith("SSH_OPEN_"), "Mismatched name for code=" + code + ": " + name);
        }
    }

    @Test
    void ambiguousOpcodes() throws Exception {
        int[] knownAmbiguities = { 30, 31, 60 };
        Collection<Integer> opcodes = SshConstants.getAmbiguousOpcodes();
        assertTrue(GenericUtils.size(opcodes) >= knownAmbiguities.length, "Not enough ambiguities found");

        for (int cmd : knownAmbiguities) {
            assertEquals(Integer.toString(cmd),
                    SshConstants.getCommandMessageName(cmd),
                    "Mismatched mnemonic for known ambiguity=" + cmd);
            assertTrue(SshConstants.isAmbiguousOpcode(cmd), "Known ambiguity not reported as such: " + cmd);
            assertTrue(opcodes.contains(cmd), "Known ambiguity=" + cmd + " not listed: " + opcodes);
        }

        for (Integer cmd : opcodes) {
            assertEquals(cmd.toString(), SshConstants.getCommandMessageName(cmd), "Mismatched mnemonic for " + cmd);
            assertTrue(SshConstants.isAmbiguousOpcode(cmd), "Opcode not detected as ambiguous: " + cmd);
        }
    }
}
