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

package org.apache.sshd.sftp.common;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SftpConstantsTest extends JUnitTestSupport {
    public SftpConstantsTest() {
        super();
    }

    @Test
    void renameModesNotMarkedAsOpcodes() {
        for (int cmd : new int[] {
                SftpConstants.SSH_FXP_RENAME_OVERWRITE,
                SftpConstants.SSH_FXP_RENAME_ATOMIC,
                SftpConstants.SSH_FXP_RENAME_NATIVE
        }) {
            String name = SftpConstants.getCommandMessageName(cmd);
            assertFalse(name.startsWith("SSH_FXP_RENAME_"), "Mismatched name for " + cmd + ": " + name);
        }
    }

    @Test
    void realPathModesNotMarkedAsOpcodes() {
        for (int cmd = SftpConstants.SSH_FXP_REALPATH_NO_CHECK; cmd <= SftpConstants.SSH_FXP_REALPATH_STAT_IF; cmd++) {
            String name = SftpConstants.getCommandMessageName(cmd);
            assertFalse(name.startsWith("SSH_FXP_REALPATH_"), "Mismatched name for " + cmd + ": " + name);
        }
    }

    @Test
    void substatusNameResolution() {
        for (int status = SftpConstants.SSH_FX_OK; status <= SftpConstants.SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK; status++) {
            String name = SftpConstants.getStatusName(status);
            assertTrue(name.startsWith("SSH_FX_"), "Failed to convert status=" + status + ": " + name);
        }
    }

    @Test
    void substatusMessageResolution() {
        for (int status = SftpConstants.SSH_FX_OK; status <= SftpConstants.SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK; status++) {
            String message = SftpHelper.resolveStatusMessage(status);
            assertTrue(GenericUtils.isNotEmpty(message), "Missing message for status=" + status);
        }
    }
}
