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

package org.apache.sshd.sftp.client.fs;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;


@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class SftpFileSystemProviderURITest extends JUnitTestSupport {

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                add(new Object[] { URI.create("sftp://username:password@host"), "host:22:username" });
                add(new Object[] { URI.create("sftp://username:password@host:22"), "host:22:username" });
                add(new Object[] { URI.create("sftp://username@host"), "host:22:username" });
                add(new Object[] { URI.create("sftp://username:password@host:2222"), "host:2222:username" });
                add(new Object[] { URI.create("sftp://username:password@host:22/path"), "host:22:username" });
            }
        };

    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "uri={0}")
    public void getFileSystemIdentifierFromUri(URI uri, String expected) {
        assertEquals(expected, SftpFileSystemProvider.getFileSystemIdentifier(uri), "Mismatch filesystem identifier");
    }

    public static List<Object[]> invalid() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                add(new Object[] { URI.create(""), "Host not provided" });
                add(new Object[] { URI.create("sftp://host:22"), "UserInfo not provided" });
                add(new Object[] { URI.create("sftp://@host:22"), "UserInfo not provided" });
            }
        };

    }

    @MethodSource("invalid")
    @ParameterizedTest(name = "uri={0}")
    public void getFileSystemIdentifierFromInvalidUri(URI uri, String message) {
       IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> SftpFileSystemProvider.getFileSystemIdentifier(uri));
       assertEquals(message, exception.getMessage());
    }


}
