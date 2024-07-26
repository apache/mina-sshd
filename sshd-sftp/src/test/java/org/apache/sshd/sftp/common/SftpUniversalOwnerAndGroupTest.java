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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SftpUniversalOwnerAndGroupTest extends JUnitTestSupport {
    public SftpUniversalOwnerAndGroupTest() {
        super();
    }

    @Test
    void nameFormat() {
        for (SftpUniversalOwnerAndGroup value : SftpUniversalOwnerAndGroup.VALUES) {
            String name = value.getName();
            assertFalse(GenericUtils.isEmpty(name), value.name() + ": empty name");
            assertEquals('@', name.charAt(name.length() - 1), value.name() + ": bad suffix");

            for (int index = 0; index < name.length() - 1; index++) {
                char ch = name.charAt(index);
                if ((ch < 'A') || (ch > 'Z')) {
                    fail("Non-uppercase character in " + name);
                }
            }
        }
    }

    @Test
    void fromName() {
        for (String name : new String[] { null, "", getCurrentTestName() }) {
            assertNull(SftpUniversalOwnerAndGroup.fromName(name), "Unexpected value for '" + name + "'");
        }

        for (SftpUniversalOwnerAndGroup expected : SftpUniversalOwnerAndGroup.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                assertSame(expected, SftpUniversalOwnerAndGroup.fromName(name), name);
                name = shuffleCase(name);
            }
        }
    }
}
