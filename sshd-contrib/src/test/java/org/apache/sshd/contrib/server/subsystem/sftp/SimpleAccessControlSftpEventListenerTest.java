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

package org.apache.sshd.contrib.server.subsystem.sftp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class SimpleAccessControlSftpEventListenerTest extends BaseTestSupport {
    private SshServer sshd;
    private int port;
    private final FileSystemFactory fileSystemFactory;

    public SimpleAccessControlSftpEventListenerTest() {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestServer();
        SftpSubsystemFactory.Builder builder = new SftpSubsystemFactory.Builder();
        builder.addSftpEventListener(SimpleAccessControlSftpEventListener.READ_ONLY_ACCESSOR);
        sshd.setSubsystemFactories(
                Collections.singletonList(builder.build()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setFileSystemFactory(fileSystemFactory);
        sshd.start();
        port = sshd.getPort();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }
    }

    @Test
    void readOnlyFileAccess() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        Files.deleteIfExists(testFile);
        Files.write(testFile, data);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(session)) {
                    String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
                    try (CloseableHandle handle = sftp.open(file, OpenMode.Read)) {
                        byte[] actual = new byte[data.length];
                        int readLen = sftp.read(handle, 0L, actual);
                        assertEquals(data.length, readLen, "Mismatched read data length");
                        assertArrayEquals(data, actual, "Mismatched read file contents");
                    }

                    try (CloseableHandle handle
                            = sftp.open(file, OpenMode.Create, OpenMode.Write, OpenMode.Read, OpenMode.Append)) {
                        sftp.write(handle, 0L, data);
                        fail("Unexpected file write success");
                    } catch (SftpException e) {
                        int status = e.getStatus();
                        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, status, "Unexpected write SFTP status code");
                    }

                    SftpClient.Attributes attrs = sftp.stat(file);
                    attrs.modifyTime(System.currentTimeMillis());
                    try {
                        sftp.setStat(file, attrs);
                        fail("Unexpected attributes modification success");
                    } catch (SftpException e) {
                        int status = e.getStatus();
                        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED,
                                status,
                                "Unexpected setAttributes SFTP status code");
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    void readOnlyDirectoryAccess() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        Files.deleteIfExists(testFile);
        Files.write(testFile, data);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(session)) {
                    String folder = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, targetPath);
                    for (SftpClient.DirEntry entry : sftp.readDir(folder)) {
                        assertNotNull(entry, "No entry");
                    }

                    String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
                    try {
                        sftp.remove(file);
                        fail("Unexpected file remove success");
                    } catch (SftpException e) {
                        int status = e.getStatus();
                        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, status, "Unexpected remove SFTP status code");
                    }

                    try {
                        sftp.mkdir(folder + "/writeAttempt");
                        fail("Unexpected folder creation success");
                    } catch (SftpException e) {
                        int status = e.getStatus();
                        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, status, "Unexpected mkdir SFTP status code");
                    }

                    try {
                        sftp.rmdir(folder);
                        fail("Unexpected folder removal success");
                    } catch (SftpException e) {
                        int status = e.getStatus();
                        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, status, "Unexpected rmdir SFTP status code");
                    }
                }
            } finally {
                client.stop();
            }
        }
    }
}
