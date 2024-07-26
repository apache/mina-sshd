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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.EnumSet;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.sftp.client.impl.SimpleSftpClientImpl;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.client.simple.BaseSimpleClientTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class SimpleSftpClientTest extends BaseSimpleClientTestSupport {
    private final Path targetPath;
    private final Path parentPath;
    private final FileSystemFactory fileSystemFactory;
    private SimpleSftpClient sftpClient;

    public SimpleSftpClientTest() throws Exception {
        targetPath = detectTargetFolder();
        parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        sshd.setFileSystemFactory(fileSystemFactory);
        client.start();
        sftpClient = new SimpleSftpClientImpl(simple);
    }

    @Test
    void sessionClosedWhenClientClosed() throws Exception {
        try (SftpClient sftp = login()) {
            assertTrue(sftp.isOpen(), "SFTP not open");

            Session session = sftp.getClientSession();
            assertTrue(session.isOpen(), "Session not open");

            sftp.close();
            assertFalse(session.isOpen(), "Session not closed");
            assertFalse(sftp.isOpen(), "SFTP not closed");
        }
    }

    @Test
    void sftpProxyCalls() throws Exception {
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");
        Path clientFile = clientFolder.resolve("file.txt");
        String remoteFileDir = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);
        String clientFileName = clientFile.getFileName().toString();
        String remoteFilePath = remoteFileDir + "/" + clientFileName;

        try (SftpClient sftp = login()) {
            sftp.mkdir(remoteFileDir);

            byte[] written
                    = (getClass().getSimpleName() + "#" + getCurrentTestName() + IoUtils.EOL).getBytes(StandardCharsets.UTF_8);
            try (SftpClient.CloseableHandle h
                    = sftp.open(remoteFilePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
                sftp.write(h, 0L, written);

                SftpClient.Attributes attrs = sftp.stat(h);
                assertNotNull(attrs, "No handle attributes");
                assertEquals(written.length, attrs.getSize(), "Mismatched remote file size");
            }

            assertTrue(Files.exists(clientFile, IoUtils.EMPTY_LINK_OPTIONS), "Remote file not created: " + clientFile);
            byte[] local = Files.readAllBytes(clientFile);
            assertArrayEquals(written, local, "Mismatched remote written data");

            try (SftpClient.CloseableHandle h = sftp.openDir(remoteFileDir)) {
                boolean matchFound = false;
                for (SftpClient.DirEntry entry : sftp.listDir(h)) {
                    String name = entry.getFilename();
                    if (clientFileName.equals(name)) {
                        matchFound = true;
                        break;
                    }
                }

                assertTrue(matchFound, "No directory entry found for " + clientFileName);
            }

            sftp.remove(remoteFilePath);
            assertFalse(Files.exists(clientFile, IoUtils.EMPTY_LINK_OPTIONS), "Remote file not removed: " + clientFile);
        }
    }

    private SftpClient login() throws IOException {
        return sftpClient.sftpLogin(TEST_LOCALHOST, port, getCurrentTestName(), getCurrentTestName());
    }
}
