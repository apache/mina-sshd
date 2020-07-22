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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class SftpConstantsTest extends JUnitTestSupport {
    public SftpConstantsTest() {
        super();
    }

    @Test
    public void testRenameModesNotMarkedAsOpcodes() {
        for (int cmd : new int[] {
                SftpConstants.SSH_FXP_RENAME_OVERWRITE,
                SftpConstants.SSH_FXP_RENAME_ATOMIC,
                SftpConstants.SSH_FXP_RENAME_NATIVE
        }) {
            String name = SftpConstants.getCommandMessageName(cmd);
            assertFalse("Mismatched name for " + cmd + ": " + name, name.startsWith("SSH_FXP_RENAME_"));
        }
    }

    @Test
    public void testRealPathModesNotMarkedAsOpcodes() {
        for (int cmd = SftpConstants.SSH_FXP_REALPATH_NO_CHECK; cmd <= SftpConstants.SSH_FXP_REALPATH_STAT_IF; cmd++) {
            String name = SftpConstants.getCommandMessageName(cmd);
            assertFalse("Mismatched name for " + cmd + ": " + name, name.startsWith("SSH_FXP_REALPATH_"));
        }
    }

    @Test
    public void testSubstatusNameResolution() {
        for (int status = SftpConstants.SSH_FX_OK; status <= SftpConstants.SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK; status++) {
            String name = SftpConstants.getStatusName(status);
            assertTrue("Failed to convert status=" + status + ": " + name, name.startsWith("SSH_FX_"));
        }
    }

    @Test
    public void testSubstatusMessageResolution() {
        for (int status = SftpConstants.SSH_FX_OK; status <= SftpConstants.SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK; status++) {
            String message = SftpHelper.resolveStatusMessage(status);
            assertTrue("Missing message for status=" + status, GenericUtils.isNotEmpty(message));
        }
    }
}
