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
package org.apache.sshd.sftp.client;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SftpDirectoryTest extends AbstractSftpClientTestSupport {
    private Path root;

    @BeforeEach
    void setUp() throws Exception {
        root = detectTargetFolder().resolve(getClass().getSimpleName()).resolve(getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(root, LinkOption.NOFOLLOW_LINKS);
        Files.createDirectories(root);
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(root));
    }

    @ParameterizedTest
    @ValueSource(strings = { "/", "///" })
    void makeDirectoryWithTrailingSlashes(String suffix) throws Exception {
        try (SftpClient sftp = createSingleSessionClient()) {
            sftp.mkdir("/parent" + suffix);
            assertTrue(Files.isDirectory(root.resolve("parent")));
            sftp.mkdir("parent/child" + suffix);
            assertTrue(Files.isDirectory(root.resolve("parent/child")));
            assertThrows(SftpException.class, () -> sftp.mkdir(suffix));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "/", "///" })
    void removeDirectoryWithTrailingSlashes(String suffix) throws Exception {
        Path directory = Files.createDirectory(root.resolve("directory"));
        try (SftpClient sftp = createSingleSessionClient()) {
            sftp.rmdir("/directory" + suffix);
            assertFalse(Files.exists(directory));
        }
    }

    @Test
    void directoryOperationsPreservePathComponents() throws Exception {
        Assumptions.assumeFalse(OsUtils.isWin32(), "Windows resolves dot path components differently");
        Path directory = Files.createDirectory(root.resolve("directory"));
        try (SftpClient sftp = createSingleSessionClient()) {
            assertThrows(SftpException.class, () -> sftp.mkdir("missing/../created/"));
            assertFalse(Files.exists(root.resolve("created")));
            assertThrows(SftpException.class, () -> sftp.mkdir("created/."));
            assertFalse(Files.exists(root.resolve("created")));
            assertThrows(SftpException.class, () -> sftp.rmdir("missing/../directory/"));
            assertThrows(SftpException.class, () -> sftp.rmdir("directory/."));
            assertTrue(Files.isDirectory(directory));
        }
    }

    @Test
    void directorySymlinkIsNotRemoved() throws Exception {
        Assumptions.assumeFalse(OsUtils.isWin32(), "Symlinks are not supported on all Windows file systems");
        Path directory = Files.createDirectory(root.resolve("directory"));
        Path link = Files.createSymbolicLink(root.resolve("link"), directory.getFileName());
        try (SftpClient sftp = createSingleSessionClient()) {
            assertTrue(sftp.lstat("link").isSymbolicLink());
            assertTrue(sftp.lstat("link/").isDirectory());
            assertThrows(SftpException.class, () -> sftp.rmdir("link/"));
            assertTrue(Files.isSymbolicLink(link));
            assertTrue(Files.isDirectory(directory));
        }
    }
}
