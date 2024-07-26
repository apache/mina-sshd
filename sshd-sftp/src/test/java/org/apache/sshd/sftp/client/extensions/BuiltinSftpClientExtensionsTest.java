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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class BuiltinSftpClientExtensionsTest extends BaseTestSupport {
    public BuiltinSftpClientExtensionsTest() {
        super();
    }

    @Test
    void fromName() {
        for (String name : new String[] { null, "", getCurrentTestName() }) {
            assertNull(BuiltinSftpClientExtensions.fromName(name), "Unexpected result for name='" + name + "'");
        }

        for (BuiltinSftpClientExtensions expected : BuiltinSftpClientExtensions.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                BuiltinSftpClientExtensions actual = BuiltinSftpClientExtensions.fromName(name);
                assertSame(expected, actual, name);
                name = shuffleCase(name);
            }
        }
    }

    @Test
    void fromType() {
        for (Class<?> clazz : new Class<?>[] { null, getClass(), SftpClientExtension.class }) {
            assertNull(BuiltinSftpClientExtensions.fromType(clazz), "Unexpected value for class=" + clazz);
        }

        for (BuiltinSftpClientExtensions expected : BuiltinSftpClientExtensions.VALUES) {
            Class<?> type = expected.getType();
            BuiltinSftpClientExtensions actual = BuiltinSftpClientExtensions.fromType(type);
            assertSame(expected, actual, type.getSimpleName());
        }
    }

    @Test
    void fromInstance() {
        for (Object instance : new Object[] { null, this }) {
            assertNull(BuiltinSftpClientExtensions.fromInstance(instance), "Unexpected value for " + instance);
        }

        SftpClient mockClient = Mockito.mock(SftpClient.class);
        RawSftpClient mockRaw = Mockito.mock(RawSftpClient.class);

        for (BuiltinSftpClientExtensions expected : BuiltinSftpClientExtensions.VALUES) {
            SftpClientExtension e = expected.create(mockClient, mockRaw);
            BuiltinSftpClientExtensions actual = BuiltinSftpClientExtensions.fromInstance(e);
            assertSame(expected, actual, expected.getName());
            assertEquals(expected.getName(), actual.getName(), "Mismatched extension name");
        }
    }
}
