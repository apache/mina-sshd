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

import java.net.URI;
import java.util.stream.Stream;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
class SftpFileSystemProviderURITest extends JUnitTestSupport {

    static Stream<Arguments> parameters() {
        return Stream.of( //
                Arguments.of(URI.create("sftp://username:password@host"), "host:22:username"),
                Arguments.of(URI.create("sftp://username:password@host:22"), "host:22:username"),
                Arguments.of(URI.create("sftp://username@host"), "host:22:username"),
                Arguments.of(URI.create("sftp://username:password@host:2222"), "host:2222:username"),
                Arguments.of(URI.create("sftp://username:password@host:22/path"), "host:22:username"));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "uri={0}")
    void getFileSystemIdentifierFromUri(URI uri, String expected) {
        assertEquals(expected, SftpFileSystemProvider.getFileSystemIdentifier(uri), "Mismatched filesystem identifier");
    }

    static Stream<Arguments> invalid() {
        return Stream.of( //
                Arguments.of(URI.create(""), "Host not provided"),
                Arguments.of(URI.create("sftp://host:22"), "UserInfo not provided"),
                Arguments.of(URI.create("sftp://@host:22"), "UserInfo not provided"));
    }

    @MethodSource("invalid")
    @ParameterizedTest(name = "uri={0}")
    void getFileSystemIdentifierFromInvalidUri(URI uri, String message) {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> SftpFileSystemProvider.getFileSystemIdentifier(uri));
        assertEquals(message, exception.getMessage());
    }

}
