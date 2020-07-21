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

package org.apache.sshd.sftp.client.extensions;

import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class BuiltinSftpClientExtensionsTest extends BaseTestSupport {
    public BuiltinSftpClientExtensionsTest() {
        super();
    }

    @Test
    public void testFromName() {
        for (String name : new String[] { null, "", getCurrentTestName() }) {
            assertNull("Unexpected result for name='" + name + "'", BuiltinSftpClientExtensions.fromName(name));
        }

        for (BuiltinSftpClientExtensions expected : BuiltinSftpClientExtensions.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                BuiltinSftpClientExtensions actual = BuiltinSftpClientExtensions.fromName(name);
                assertSame(name, expected, actual);
                name = shuffleCase(name);
            }
        }
    }

    @Test
    public void testFromType() {
        for (Class<?> clazz : new Class<?>[] { null, getClass(), SftpClientExtension.class }) {
            assertNull("Unexpected value for class=" + clazz, BuiltinSftpClientExtensions.fromType(clazz));
        }

        for (BuiltinSftpClientExtensions expected : BuiltinSftpClientExtensions.VALUES) {
            Class<?> type = expected.getType();
            BuiltinSftpClientExtensions actual = BuiltinSftpClientExtensions.fromType(type);
            assertSame(type.getSimpleName(), expected, actual);
        }
    }

    @Test
    public void testFromInstance() {
        for (Object instance : new Object[] { null, this }) {
            assertNull("Unexpected value for " + instance, BuiltinSftpClientExtensions.fromInstance(instance));
        }

        SftpClient mockClient = Mockito.mock(SftpClient.class);
        RawSftpClient mockRaw = Mockito.mock(RawSftpClient.class);

        for (BuiltinSftpClientExtensions expected : BuiltinSftpClientExtensions.VALUES) {
            SftpClientExtension e = expected.create(mockClient, mockRaw);
            BuiltinSftpClientExtensions actual = BuiltinSftpClientExtensions.fromInstance(e);
            assertSame(expected.getName(), expected, actual);
            assertEquals("Mismatched extension name", expected.getName(), actual.getName());
        }
    }
}
