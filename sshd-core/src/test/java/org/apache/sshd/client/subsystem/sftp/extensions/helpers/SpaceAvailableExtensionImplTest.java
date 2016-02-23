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

package org.apache.sshd.client.subsystem.sftp.extensions.helpers;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.AbstractSftpClientTestSupport;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.extensions.SpaceAvailableExtension;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.extensions.SpaceAvailableExtensionInfo;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystem;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SpaceAvailableExtensionImplTest extends AbstractSftpClientTestSupport {
    public SpaceAvailableExtensionImplTest() throws IOException {
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
    public void testFileStoreReport() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path parentPath = targetPath.getParent();
        FileStore store = Files.getFileStore(lclSftp.getRoot());
        final String queryPath = Utils.resolveRelativeRemotePath(parentPath, lclSftp);
        final SpaceAvailableExtensionInfo expected = new SpaceAvailableExtensionInfo(store);
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory() {
            @Override
            public Command create() {
                return new SftpSubsystem(getExecutorService(), isShutdownOnExit(), getUnsupportedAttributePolicy()) {
                    @Override
                    protected SpaceAvailableExtensionInfo doSpaceAvailable(int id, String path) throws IOException {
                        if (!queryPath.equals(path)) {
                            throw new StreamCorruptedException("Mismatched query paths: expected=" + queryPath + ", actual=" + path);
                        }

                        return expected;
                    }
                };
            }
        }));

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    SpaceAvailableExtension ext = assertExtensionCreated(sftp, SpaceAvailableExtension.class);
                    SpaceAvailableExtensionInfo actual = ext.available(queryPath);
                    assertEquals("Mismatched information", expected, actual);
                }
            } finally {
                client.stop();
            }
        }
    }
}
