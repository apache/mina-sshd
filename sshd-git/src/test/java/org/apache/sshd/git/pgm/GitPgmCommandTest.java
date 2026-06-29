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
package org.apache.sshd.git.pgm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.rmi.RemoteException;
import java.util.Collections;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.git.GitLocationResolver;
import org.apache.sshd.git.GitTestSupport;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.util.SystemReader;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Tests for running git commands.
 */
@TestMethodOrder(MethodName.class)
class GitPgmCommandTest extends GitTestSupport {

    GitPgmCommandTest() {
        super();
    }

    @Test
    void gitPgm() throws Exception {
        Path serverDir = getTempTargetRelativeFile(getClass().getSimpleName());
        SystemReader defaultSystemReader = mockGitConfig(serverDir.getParent());
        try (SshServer sshd = setupTestServer()) {
            sshd.setCommandFactory(new GitPgmCommandFactory(GitLocationResolver.constantPath(serverDir)));
            sshd.start();

            int port = sshd.getPort();
            try {
                CommonTestSupportUtils.deleteRecursive(serverDir);
                runGitCommands(getCurrentTestName(), port, serverDir);
            } finally {
                sshd.stop();
            }
        } finally {
            SystemReader.setInstance(defaultSystemReader);
        }
    }

    private void runGitCommands(String testName, int port, Path serverDir) throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();
            try (ClientSession session = client.connect(testName, SshdSocketAddress.LOCALHOST_IPV4, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(testName);
                session.auth().verify(AUTH_TIMEOUT);

                Path repo = serverDir.resolve(testName);
                Path readmeFile;
                try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
                    readmeFile = Files.write(repo.resolve("readme.txt"), Collections.singletonList("README"));
                    git.add().addFilepattern("readme.txt").call();
                    git.commit() //
                            .setMessage("First Commit") //
                            .setCommitter(testName, "sshd@apache.org") //
                            .setAuthor(testName, "sshd@apache.org") //
                            .call();
                }
                String commandPrefix = "git --git-dir " + repo.getFileName();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream();
                RemoteException ex = assertThrows(RemoteException.class,
                        () -> session.executeRemoteCommand(commandPrefix + " add " + readmeFile.getFileName(), out, err,
                                StandardCharsets.UTF_8, AUTH_TIMEOUT));
                assertTrue(ex.getMessage().contains("Remote command failed"));
                assertTrue(err.toString().contains("not allowed"));
                out.reset();
                err.reset();
                session.executeRemoteCommand(commandPrefix + " log ", out, err, StandardCharsets.UTF_8, AUTH_TIMEOUT);
                String log = out.toString();
                assertTrue(log.contains("First Commit"));
                assertTrue(log.contains(testName));
                assertTrue(log.contains("sshd@apache.org"));
                out.reset();
                err.reset();
                session.executeRemoteCommand(commandPrefix + " archive -o archive.zip --format zip HEAD", out, err,
                        StandardCharsets.UTF_8, AUTH_TIMEOUT);
                assertFalse(Files.exists(repo.resolve("archive.zip")));
                assertFalse(Files.exists(serverDir.resolve("archive.zip")));
                ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
                try (ZipInputStream zIn = new ZipInputStream(in)) {
                    ZipEntry entry = zIn.getNextEntry();
                    assertEquals(readmeFile.getFileName().toString(), entry.getName());
                    ByteArrayOutputStream content = new ByteArrayOutputStream();
                    byte[] chunk = new byte[1024];
                    int n = 0;
                    while ((n = zIn.read(chunk)) >= 0) {
                        content.write(chunk, 0, n);
                    }
                    zIn.closeEntry();
                    assertEquals(Files.size(readmeFile), content.size());
                }
            } finally {
                client.stop();
            }
        }
    }
}
