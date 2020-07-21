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
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
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

    @Override
    public void setUp() throws Exception {
        super.setUp();
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        sshd.setFileSystemFactory(fileSystemFactory);
        client.start();
        sftpClient = new SimpleSftpClientImpl(simple);
    }

    @Test
    public void testSessionClosedWhenClientClosed() throws Exception {
        try (SftpClient sftp = login()) {
            assertTrue("SFTP not open", sftp.isOpen());

            Session session = sftp.getClientSession();
            assertTrue("Session not open", session.isOpen());

            sftp.close();
            assertFalse("Session not closed", session.isOpen());
            assertFalse("SFTP not closed", sftp.isOpen());
        }
    }

    @Test
    public void testSftpProxyCalls() throws Exception {
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
                assertNotNull("No handle attributes", attrs);
                assertEquals("Mismatched remote file size", written.length, attrs.getSize());
            }

            assertTrue("Remote file not created: " + clientFile, Files.exists(clientFile, IoUtils.EMPTY_LINK_OPTIONS));
            byte[] local = Files.readAllBytes(clientFile);
            assertArrayEquals("Mismatched remote written data", written, local);

            try (SftpClient.CloseableHandle h = sftp.openDir(remoteFileDir)) {
                boolean matchFound = false;
                for (SftpClient.DirEntry entry : sftp.listDir(h)) {
                    String name = entry.getFilename();
                    if (clientFileName.equals(name)) {
                        matchFound = true;
                        break;
                    }
                }

                assertTrue("No directory entry found for " + clientFileName, matchFound);
            }

            sftp.remove(remoteFilePath);
            assertFalse("Remote file not removed: " + clientFile, Files.exists(clientFile, IoUtils.EMPTY_LINK_OPTIONS));
        }
    }

    private SftpClient login() throws IOException {
        return sftpClient.sftpLogin(TEST_LOCALHOST, port, getCurrentTestName(), getCurrentTestName());
    }
}
