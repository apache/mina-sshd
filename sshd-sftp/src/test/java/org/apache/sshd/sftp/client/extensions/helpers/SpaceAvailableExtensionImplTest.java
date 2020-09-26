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

package org.apache.sshd.sftp.client.extensions.helpers;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.SpaceAvailableExtension;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.SpaceAvailableExtensionInfo;
import org.apache.sshd.sftp.server.SftpSubsystem;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
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

    @Test
    public void testFileStoreReport() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path parentPath = targetPath.getParent();
        FileStore store = Files.getFileStore(lclSftp.getRoot());
        final String queryPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclSftp);
        final SpaceAvailableExtensionInfo expected = new SpaceAvailableExtensionInfo(store);

        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory() {
            @Override
            public Command createSubsystem(ChannelSession channel) throws IOException {
                return new SftpSubsystem(
                        resolveExecutorService(),
                        getUnsupportedAttributePolicy(), getFileSystemAccessor(), getErrorStatusDataHandler()) {
                    @Override
                    protected SpaceAvailableExtensionInfo doSpaceAvailable(int id, String path) throws IOException {
                        if (!queryPath.equals(path)) {
                            throw new StreamCorruptedException(
                                    "Mismatched query paths: expected=" + queryPath + ", actual=" + path);
                        }

                        return expected;
                    }
                };
            }
        }));

        try (SftpClient sftp = createSingleSessionClient()) {
            SpaceAvailableExtension ext = assertExtensionCreated(sftp, SpaceAvailableExtension.class);
            SpaceAvailableExtensionInfo actual = ext.available(queryPath);
            assertEquals("Mismatched information", expected, actual);
        } finally {
            sshd.setSubsystemFactories(factories);
        }
    }
}
