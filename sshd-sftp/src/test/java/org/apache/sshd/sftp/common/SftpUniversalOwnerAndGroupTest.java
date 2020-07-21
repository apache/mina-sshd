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
public class SftpUniversalOwnerAndGroupTest extends JUnitTestSupport {
    public SftpUniversalOwnerAndGroupTest() {
        super();
    }

    @Test
    public void testNameFormat() {
        for (SftpUniversalOwnerAndGroup value : SftpUniversalOwnerAndGroup.VALUES) {
            String name = value.getName();
            assertFalse(value.name() + ": empty name", GenericUtils.isEmpty(name));
            assertTrue(value.name() + ": bad suffix", name.charAt(name.length() - 1) == '@');

            for (int index = 0; index < name.length() - 1; index++) {
                char ch = name.charAt(index);
                if ((ch < 'A') || (ch > 'Z')) {
                    fail("Non-uppercase character in " + name);
                }
            }
        }
    }

    @Test
    public void testFromName() {
        for (String name : new String[] { null, "", getCurrentTestName() }) {
            assertNull("Unexpected value for '" + name + "'", SftpUniversalOwnerAndGroup.fromName(name));
        }

        for (SftpUniversalOwnerAndGroup expected : SftpUniversalOwnerAndGroup.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                assertSame(name, expected, SftpUniversalOwnerAndGroup.fromName(name));
                name = shuffleCase(name);
            }
        }
    }
}
