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

package org.apache.sshd.sftp.client.impl;

import java.io.IOException;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.util.EnumSet;

import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("checkstyle:MethodCount")
public class SftpRemotePathChannelTest extends AbstractSftpClientTestSupport {
    public SftpRemotePathChannelTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @Test // see SSHD-697
    public void testFileChannel() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path lclFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(lclFile);
        byte[] expected
                = (getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")").getBytes(StandardCharsets.UTF_8);

        Path parentPath = targetPath.getParent();
        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);

        try (SftpClient sftp = createSingleSessionClient();
             FileChannel fc = sftp.openRemotePathChannel(
                     remFilePath, EnumSet.of(
                             StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE))) {
            int writeLen = fc.write(ByteBuffer.wrap(expected));
            assertEquals("Mismatched written length", expected.length, writeLen);

            FileChannel fcPos = fc.position(0L);
            assertSame("Mismatched positioned file channel", fc, fcPos);

            byte[] actual = new byte[expected.length];
            int readLen = fc.read(ByteBuffer.wrap(actual));
            assertEquals("Mismatched read len", writeLen, readLen);
            assertArrayEquals("Mismatched read data", expected, actual);
        }

        byte[] actual = Files.readAllBytes(lclFile);
        assertArrayEquals("Mismatched persisted data", expected, actual);
    }

    @Test // see SSHD-967
    public void testTransferToFileChannel() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-src.txt");
        Path parentPath = targetPath.getParent();

        Files.deleteIfExists(srcFile);
        try (Writer output = Files.newBufferedWriter(srcFile, StandardCharsets.UTF_8)) {
            String seed = getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")";
            for (long totalWritten = 0L;
                 totalWritten <= SftpModuleProperties.COPY_BUF_SIZE.getRequiredDefault();
                 totalWritten += seed.length()) {
                output.append(seed).append(System.lineSeparator());
            }
        }

        byte[] expected = Files.readAllBytes(srcFile);
        Path dstFile = srcFile.getParent().resolve(getCurrentTestName() + "-dst.txt");
        Files.deleteIfExists(dstFile);

        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);
        try (SftpClient sftp = createSingleSessionClient();
             FileChannel srcChannel = sftp.openRemotePathChannel(
                     remFilePath, EnumSet.of(StandardOpenOption.READ));
             FileChannel dstChannel = FileChannel.open(dstFile,
                     StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            long numXfered = srcChannel.transferTo(0L, expected.length, dstChannel);
            assertEquals("Mismatched reported transfer count", expected.length, numXfered);
        }

        byte[] actual = Files.readAllBytes(dstFile);
        assertEquals("Mismatched transfered size", expected.length, actual.length);
        assertArrayEquals("Mismatched transferred data", expected, actual);
    }

    @Test(timeout = 10000) // see SSHD-970
    public void testTransferToFileChannelLoopFile() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-src.txt");
        Path parentPath = targetPath.getParent();

        Files.deleteIfExists(srcFile);
        try (Writer output = Files.newBufferedWriter(srcFile, StandardCharsets.UTF_8)) {
            String seed = getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")";
            output.append(seed).append(System.lineSeparator());
        }

        byte[] expected = Files.readAllBytes(srcFile);
        Path dstFile = srcFile.getParent().resolve(getCurrentTestName() + "-dst.txt");
        Files.deleteIfExists(dstFile);

        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);
        try (SftpClient sftp = createSingleSessionClient();
             FileChannel srcChannel = sftp.openRemotePathChannel(
                     remFilePath, EnumSet.of(StandardOpenOption.READ));
             FileChannel dstChannel = FileChannel.open(dstFile,
                     StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            // SftpRemotePathChannel.DEFAULT_TRANSFER_BUFFER_SIZE > expected.length => Infinite loop
            long numXfered
                    = srcChannel.transferTo(0L, SftpModuleProperties.COPY_BUF_SIZE.getRequiredDefault(), dstChannel);
            assertEquals("Mismatched reported transfer count", expected.length, numXfered);
        }

        byte[] actual = Files.readAllBytes(dstFile);
        assertEquals("Mismatched transfered size", expected.length, actual.length);
        assertArrayEquals("Mismatched transferred data", expected, actual);
    }

    @Test // see SSHD-967
    public void testTransferFromFileChannel() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-src.txt");
        Path parentPath = targetPath.getParent();

        Files.deleteIfExists(srcFile);
        try (Writer output = Files.newBufferedWriter(srcFile, StandardCharsets.UTF_8)) {
            String seed = getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")";
            for (long totalWritten = 0L;
                 totalWritten <= SftpModuleProperties.COPY_BUF_SIZE.getRequiredDefault();
                 totalWritten += seed.length()) {
                output.append(seed).append(System.lineSeparator());
            }
        }

        byte[] expected = Files.readAllBytes(srcFile);
        Path dstFile = srcFile.getParent().resolve(getCurrentTestName() + "-dst.txt");
        Files.deleteIfExists(dstFile);

        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, dstFile);
        try (SftpClient sftp = createSingleSessionClient();
             FileChannel dstChannel = sftp.openRemotePathChannel(
                     remFilePath, EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE));
             FileChannel srcChannel = FileChannel.open(srcFile, StandardOpenOption.READ)) {
            long numXfered = dstChannel.transferFrom(srcChannel, 0L, expected.length);
            assertEquals("Mismatched reported transfer count", expected.length, numXfered);
        }

        byte[] actual = Files.readAllBytes(dstFile);
        assertEquals("Mismatched transfered size", expected.length, actual.length);
        assertArrayEquals("Mismatched transferred data", expected, actual);
    }
}
