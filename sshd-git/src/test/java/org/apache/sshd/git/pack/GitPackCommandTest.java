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
package org.apache.sshd.git.pack;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import com.jcraft.jsch.JSch;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.git.GitLocationResolver;
import org.apache.sshd.git.transport.GitSshdSessionFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GitPackCommandTest extends BaseTestSupport {
    public GitPackCommandTest() {
        super();
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Override
    protected SshServer setupTestServer() {
        SshServer server = super.setupTestServer();
        server.setPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
        return server;
    }

    @Test
    public void testGitPack() throws Exception {
        Assume.assumeFalse("On windows this activates TortoisePlink", OsUtils.isWin32());

        Path gitRootDir = getTempTargetRelativeFile(getClass().getSimpleName());
        try (SshServer sshd = setupTestServer()) {
            Path serverRootDir = gitRootDir.resolve("server");
            sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
            sshd.setCommandFactory(new GitPackCommandFactory(GitLocationResolver.constantPath(serverRootDir)));
            sshd.start();

            int port = sshd.getPort();
            try {
                Path serverDir = serverRootDir.resolve(getCurrentTestName() + Constants.DOT_GIT_EXT);
                CommonTestSupportUtils.deleteRecursive(serverDir);
                Git.init().setBare(true).setDirectory(serverDir.toFile()).call();

                JSch.setConfig("StrictHostKeyChecking", "no");
                CredentialsProvider
                        .setDefault(new UsernamePasswordCredentialsProvider(getCurrentTestName(), getCurrentTestName()));
                Path localRootDir = gitRootDir.resolve("local");
                Path localDir = localRootDir.resolve(serverDir.getFileName());
                CommonTestSupportUtils.deleteRecursive(localDir);

                SshClient client = SshClient.setUpDefaultClient();
                SshSessionFactory.setInstance(new GitSshdSessionFactory(client));
                try (Git git = Git.cloneRepository()
                        .setURI("ssh://" + getCurrentTestName() + "@" + TEST_LOCALHOST + ":" + port + "/"
                                + serverDir.getFileName())
                        .setDirectory(localDir.toFile())
                        .call()) {
                    assertTrue("Client not started after clone", client.isStarted());
                    git.commit().setMessage("First Commit").setCommitter(getCurrentTestName(), "sshd@apache.org").call();
                    git.push().call();
                    assertTrue("Client not started after 1st push", client.isStarted());

                    Path readmeFile = Files.createFile(localDir.resolve("readme.txt"));
                    git.add().addFilepattern(readmeFile.getFileName().toString()).call();
                    git.commit().setMessage(getCurrentTestName()).setCommitter(getCurrentTestName(), "sshd@apache.org").call();
                    git.push().call();
                    assertTrue("Client not started after 2nd push", client.isStarted());

                    git.pull().setRebase(true).call();
                    assertTrue("Client not started after rebase", client.isStarted());
                } finally {
                    client.stop();
                }

                assertFalse("Client not stopped after exit", client.isStarted());
            } finally {
                sshd.stop();
            }
        }
    }
}
