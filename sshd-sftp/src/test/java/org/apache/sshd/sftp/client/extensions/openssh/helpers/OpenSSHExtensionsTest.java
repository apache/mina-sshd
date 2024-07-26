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

package org.apache.sshd.sftp.client.extensions.openssh.helpers;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHFsyncExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHLimitsExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHLimitsExtensionInfo;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHPosixRenameExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatExtensionInfo;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatHandleExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatPathExtension;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.common.extensions.openssh.AbstractOpenSSHExtensionParser.OpenSSHExtension;
import org.apache.sshd.sftp.common.extensions.openssh.FstatVfsExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.StatVfsExtensionParser;
import org.apache.sshd.sftp.server.SftpSubsystem;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class OpenSSHExtensionsTest extends AbstractSftpClientTestSupport {
    public OpenSSHExtensionsTest() throws IOException {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        setupServer();
    }

    @Test
    void posixRename() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp.resolve("client"));
        try (SftpClient sftp = createSingleSessionClient()) {
            OpenSSHPosixRenameExtension rename = assertExtensionCreated(sftp, OpenSSHPosixRenameExtension.class);

            Path file1 = clientFolder.resolve("file-1.txt");
            String file1Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file1);
            try (OutputStream os = sftp.write(file1Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                os.write((getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8));
            }

            Path file2 = clientFolder.resolve("file-2.txt");
            String file2Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file2);
            Path file3 = clientFolder.resolve("file-3.txt");
            String file3Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file3);
            try {
                rename.posixRename(file2Path, file3Path);
                fail("Unxpected rename success of " + file2Path + " => " + file3Path);
            } catch (SftpException e) {
                assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus(),
                        "Mismatched status for failed rename of " + file2Path + " => " + file3Path);
            }

            try (OutputStream os = sftp.write(file2Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                os.write("h".getBytes(StandardCharsets.UTF_8));
            }

            rename.posixRename(file1Path, file2Path);
        }
    }

    @Test
    void fsync() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + ".txt");
        byte[] expected = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);

        Path parentPath = targetPath.getParent();
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);
        try (SftpClient sftp = createSingleSessionClient()) {
            OpenSSHFsyncExtension fsync = assertExtensionCreated(sftp, OpenSSHFsyncExtension.class);
            try (CloseableHandle fileHandle = sftp.open(srcPath, SftpClient.OpenMode.Write, SftpClient.OpenMode.Create)) {
                sftp.write(fileHandle, 0L, expected);
                fsync.fsync(fileHandle);

                byte[] actual = Files.readAllBytes(srcFile);
                assertArrayEquals(expected, actual, "Mismatched written data");
            }
        }
    }

    @Test
    void stat() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + ".txt");
        Files.write(srcFile, (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8),
                IoUtils.EMPTY_OPEN_OPTIONS);
        Path parentPath = targetPath.getParent();
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);

        OpenSSHStatExtensionInfo expected = new OpenSSHStatExtensionInfo();
        expected.f_bavail = Short.MAX_VALUE;
        expected.f_bfree = Integer.MAX_VALUE;
        expected.f_blocks = Short.MAX_VALUE;
        expected.f_bsize = IoUtils.DEFAULT_COPY_SIZE;
        expected.f_favail = Long.MAX_VALUE;
        expected.f_ffree = Byte.MAX_VALUE;
        expected.f_files = 3777347L;
        expected.f_flag = OpenSSHStatExtensionInfo.SSH_FXE_STATVFS_ST_RDONLY;
        expected.f_frsize = 7365L;
        expected.f_fsid = 1L;
        expected.f_namemax = 256;

        AtomicReference<String> extensionHolder = new AtomicReference<>(null);
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory() {
            @Override
            public Command createSubsystem(ChannelSession channel) throws IOException {
                return new SftpSubsystem(channel, this) {
                    @Override
                    protected List<OpenSSHExtension> resolveOpenSSHExtensions(ServerSession session) {
                        List<OpenSSHExtension> original = super.resolveOpenSSHExtensions(session);
                        int numOriginal = GenericUtils.size(original);
                        List<OpenSSHExtension> result = new ArrayList<>(numOriginal + 2);
                        if (numOriginal > 0) {
                            result.addAll(original);
                        }

                        for (String name : new String[] { StatVfsExtensionParser.NAME, FstatVfsExtensionParser.NAME }) {
                            result.add(new OpenSSHExtension(name, "2"));
                        }

                        return result;
                    }

                    @Override
                    protected void executeExtendedCommand(Buffer buffer, int id, String extension) throws IOException {
                        if (StatVfsExtensionParser.NAME.equals(extension)
                                || FstatVfsExtensionParser.NAME.equals(extension)) {
                            String prev = extensionHolder.getAndSet(extension);
                            if (prev != null) {
                                throw new StreamCorruptedException(
                                        "executeExtendedCommand(" + extension + ") previous not null: " + prev);
                            }

                            buffer = prepareReply(buffer);
                            buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
                            buffer.putInt(id);
                            OpenSSHStatExtensionInfo.encode(buffer, expected);
                            send(buffer);
                        } else {
                            super.executeExtendedCommand(buffer, id, extension);
                        }
                    }
                };
            }
        }));

        try (SftpClient sftp = createSingleSessionClient()) {
            OpenSSHStatPathExtension pathStat = assertExtensionCreated(sftp, OpenSSHStatPathExtension.class);
            OpenSSHStatExtensionInfo actual = pathStat.stat(srcPath);
            String invokedExtension = extensionHolder.getAndSet(null);
            assertEquals(pathStat.getName(), invokedExtension, "Mismatched invoked extension");
            assertFieldsEqual(invokedExtension, expected, actual);

            try (CloseableHandle handle = sftp.open(srcPath)) {
                OpenSSHStatHandleExtension handleStat = assertExtensionCreated(sftp, OpenSSHStatHandleExtension.class);
                actual = handleStat.stat(handle);
                invokedExtension = extensionHolder.getAndSet(null);
                assertEquals(handleStat.getName(), invokedExtension, "Mismatched invoked extension");
                assertFieldsEqual(invokedExtension, expected, actual);
            }
        }
    }

    // see SSHD-1233
    @Test
    void limits() throws Exception {
        try (SftpClient sftp = createSingleSessionClient()) {
            OpenSSHLimitsExtension ext = assertExtensionCreated(sftp, OpenSSHLimitsExtension.class);
            OpenSSHLimitsExtensionInfo expected = new OpenSSHLimitsExtensionInfo(sftp.getClientChannel());
            OpenSSHLimitsExtensionInfo actual = ext.limits();
            assertFieldsEqual(ext.getName(), expected, actual);
        }
    }
}
