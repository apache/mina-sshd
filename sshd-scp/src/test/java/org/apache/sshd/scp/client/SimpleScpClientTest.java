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

package org.apache.sshd.scp.client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.client.simple.BaseSimpleClientTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SimpleScpClientTest extends BaseSimpleClientTestSupport {
    private final Path targetPath;
    private final Path parentPath;
    private final FileSystemFactory fileSystemFactory;
    private SimpleScpClient scpClient;

    public SimpleScpClientTest() throws Exception {
        targetPath = detectTargetFolder();
        parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setFileSystemFactory(fileSystemFactory);
        client.start();
        scpClient = new SimpleScpClientImpl(simple);
    }

    @Test
    public void testSessionClosedWhenClientClosed() throws Exception {
        try (CloseableScpClient scp = login()) {
            assertTrue("SCP not open", scp.isOpen());

            Session session = scp.getClientSession();
            assertTrue("Session not open", session.isOpen());

            scp.close();
            assertFalse("Session not closed", session.isOpen());
            assertFalse("SCP not closed", scp.isOpen());
        }
    }

    @Test
    public void testScpUploadProxy() throws Exception {
        try (CloseableScpClient scp = login()) {
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
            Path localFile = localDir.resolve("file.txt");
            String data = getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL;
            byte[] written = CommonTestSupportUtils.writeFile(localFile, data);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            Path remoteFile = remoteDir.resolve(localFile.getFileName());
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
            scp.upload(localFile, remotePath);

            byte[] uploaded = Files.readAllBytes(remoteFile);
            assertArrayEquals("Mismatched uploaded data", written, uploaded);
        }
    }

    @Test
    public void testScpDownloadProxy() throws Exception {
        try (CloseableScpClient scp = login()) {
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            Path remoteFile = remoteDir.resolve("file.txt");
            String data = getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL;
            byte[] written = CommonTestSupportUtils.writeFile(remoteFile, data);
            Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
            Path localFile = localDir.resolve(remoteFile.getFileName());
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
            scp.download(remotePath, localFile);

            byte[] downloaded = Files.readAllBytes(localFile);
            assertArrayEquals("Mismatched downloaded data", written, downloaded);
        }
    }

    private CloseableScpClient login() throws IOException {
        return scpClient.scpLogin(TEST_LOCALHOST, port, getCurrentTestName(), getCurrentTestName());
    }
}
