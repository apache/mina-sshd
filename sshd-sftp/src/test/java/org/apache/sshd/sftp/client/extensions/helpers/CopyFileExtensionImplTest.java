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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.CopyFileExtension;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CopyFileExtensionImplTest extends AbstractSftpClientTestSupport {
    public CopyFileExtensionImplTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @Test
    public void testCopyFileExtension() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath,
                SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve("src.txt");
        Files.write(srcFile, data, IoUtils.EMPTY_OPEN_OPTIONS);

        Path parentPath = targetPath.getParent();
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);
        Path dstFile = lclSftp.resolve("dst.txt");
        String dstPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, dstFile);

        LinkOption[] options = IoUtils.getLinkOptions(true);
        assertFalse("Destination file unexpectedly exists", Files.exists(dstFile, options));

        try (SftpClient sftp = createSingleSessionClient()) {
            CopyFileExtension ext = assertExtensionCreated(sftp, CopyFileExtension.class);
            ext.copyFile(srcPath, dstPath, false);
            assertTrue("Source file not preserved", Files.exists(srcFile, options));
            assertTrue("Destination file not created", Files.exists(dstFile, options));

            byte[] actual = Files.readAllBytes(dstFile);
            assertArrayEquals("Mismatched copied data", data, actual);

            try {
                ext.copyFile(srcPath, dstPath, false);
                fail("Unexpected success to overwrite existing destination: " + dstFile);
            } catch (IOException e) {
                assertTrue("Not an SftpException", e instanceof SftpException);
            }
        }
    }
}
