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

package org.apache.sshd.contrib.server.scp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.scp.client.ScpClient;
import org.apache.sshd.scp.client.ScpClientCreator;
import org.apache.sshd.scp.common.ScpException;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SimpleAccessControlScpEventListenerTest extends BaseTestSupport {
    private SshServer sshd;
    private int port;
    private final FileSystemFactory fileSystemFactory;

    public SimpleAccessControlScpEventListenerTest() {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setFileSystemFactory(fileSystemFactory);
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }
    }

    @Test
    public void testReadOnlyScpTransferEventListener() throws Exception {
        sshd.setCommandFactory(new ScpCommandFactory.Builder()
                .addEventListener(SimpleAccessControlScpEventListener.READ_ONLY_ACCESSOR)
                .build());

        try (SshClient client = setupTestClient()) {
            client.start();
            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                ScpClientCreator creator = ScpClientCreator.instance();
                ScpClient scp = creator.createScpClient(session);
                Path targetPath = detectTargetFolder();
                Path parentPath = targetPath.getParent();
                Path scpRoot = CommonTestSupportUtils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX,
                        getClass().getSimpleName(), getCurrentTestName());
                CommonTestSupportUtils.deleteRecursive(scpRoot);

                Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                Path remoteFile = remoteDir.resolve("file.txt");
                String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
                byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
                Files.write(remoteFile, data);
                byte[] downloaded = scp.downloadBytes(remotePath);
                assertArrayEquals("Mismatched downloaded data", data, downloaded);

                try {
                    scp.upload(data, remotePath, EnumSet.allOf(PosixFilePermission.class), null);
                    fail("Unexpected upload success");
                } catch (ScpException e) {
                    // expected - ignored
                }
            } finally {
                client.stop();
            }
        }
    }
}
