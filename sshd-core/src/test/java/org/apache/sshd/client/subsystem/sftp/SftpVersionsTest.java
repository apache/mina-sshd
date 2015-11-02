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

package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.SftpClient.Attributes;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystem;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class SftpVersionsTest extends AbstractSftpClientTestSupport {
    private static final List<Integer> VERSIONS =
            Collections.unmodifiableList(new ArrayList<Integer>() {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    for (int version = SftpSubsystem.LOWER_SFTP_IMPL; version <= SftpSubsystem.HIGHER_SFTP_IMPL; version++) {
                        add(Integer.valueOf(version));
                    }
                }
            });

    private final int version;

    public SftpVersionsTest(int version) throws IOException {
        this.version = version;
    }

    @Parameters(name = "version={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(VERSIONS);
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
    public void testSftpVersionSelector() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient(version)) {
                    assertEquals("Mismatched negotiated version", version, sftp.getVersion());
                }
            } finally {
                client.stop();
            }
        }
    }
    @Test   // see SSHD-572
    public void testSftpFileTimesUpdate() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path lclFile = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-" + version + ".txt");
        Files.write(lclFile, getClass().getName().getBytes(StandardCharsets.UTF_8));
        Path parentPath = targetPath.getParent();
        String remotePath = Utils.resolveRelativeRemotePath(parentPath, lclFile);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient(version)) {
                    Attributes attrs = sftp.lstat(remotePath);
                    long expectedSeconds = TimeUnit.SECONDS.convert(System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1L), TimeUnit.MILLISECONDS);
                    attrs.modifyTime(expectedSeconds);
                    sftp.setStat(remotePath, attrs);

                    attrs = sftp.lstat(remotePath);
                    long actualSeconds = attrs.getModifyTime().to(TimeUnit.SECONDS);
                    // The NTFS file system delays updates to the last access time for a file by up to 1 hour after the last access
                    if (expectedSeconds != actualSeconds) {
                        System.err.append("Mismatched last modified time for ").append(lclFile.toString())
                                  .append(" - expected=").append(String.valueOf(expectedSeconds))
                                  .append('[').append(new Date(TimeUnit.SECONDS.toMillis(expectedSeconds)).toString()).append(']')
                                  .append(", actual=").append(String.valueOf(actualSeconds))
                                  .append('[').append(new Date(TimeUnit.SECONDS.toMillis(actualSeconds)).toString()).append(']')
                                  .println();
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

}
