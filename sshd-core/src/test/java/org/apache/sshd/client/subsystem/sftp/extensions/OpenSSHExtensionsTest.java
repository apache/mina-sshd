/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.client.subsystem.sftp.extensions;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.AbstractSftpClientTestSupport;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.extensions.openssh.OpenSSHFsyncExtension;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OpenSSHExtensionsTest extends AbstractSftpClientTestSupport {
    public OpenSSHExtensionsTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @After
    public void tearDown() throws Exception {
        tearDownServer();
    }

    @Test
    public void testFsync() throws IOException {
        Path targetPath = detectTargetFolder().toPath();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + ".txt");
        byte[] expected=(getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);

        Path parentPath = targetPath.getParent();
        String srcPath = Utils.resolveRelativeRemotePath(parentPath, srcFile);
        try(SshClient client = SshClient.setUpDefaultClient()) {
            client.start();
            
            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);
                
                try(SftpClient sftp = session.createSftpClient()) {
                    OpenSSHFsyncExtension fsync = assertExtensionCreated(sftp, OpenSSHFsyncExtension.class);
                    try(CloseableHandle fileHandle = sftp.open(srcPath, SftpClient.OpenMode.Write, SftpClient.OpenMode.Create)) {
                        sftp.write(fileHandle, 0L, expected);
                        fsync.fsync(fileHandle);

                        byte[] actual = Files.readAllBytes(srcFile);
                        assertArrayEquals("Mismatched written data", expected,  actual);
                    }
                }
            } finally {
                client.stop();
            }
        }
    }
}
