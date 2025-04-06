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
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.git.GitLocationResolver;
import org.apache.sshd.git.GitModuleProperties;
import org.apache.sshd.git.transport.GitSshdSessionFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.GitProtocolConstants;
import org.eclipse.jgit.transport.ReceivePack;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.UploadPack;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Tests for using git over ssh.
 */
@TestMethodOrder(MethodName.class)
class GitPackCommandTest extends BaseTestSupport {

    GitPackCommandTest() {
        super();
    }

    @BeforeAll
    static void jschInit() {
        JSchLogger.init();
    }

    @Override
    protected SshServer setupTestServer() {
        SshServer server = super.setupTestServer();
        server.setPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
        return server;
    }

    @Test
    void gitPack() throws Exception {
        Assumptions.assumeFalse(OsUtils.isWin32(), "On windows this activates TortoisePlink");

        Path gitRootDir = getTempTargetRelativeFile(getClass().getSimpleName());
        try (SshServer sshd = setupTestServer()) {
            GitPackTestConfig packConfig = new GitPackTestConfig();
            Path serverRootDir = gitRootDir.resolve("server");
            sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
            sshd.setCommandFactory(new GitPackCommandFactory(GitLocationResolver.constantPath(serverRootDir))
                    .withGitPackConfiguration(packConfig));
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
                    assertTrue(client.isStarted(), "Client not started after clone");
                    git.commit().setMessage("First Commit").setCommitter(getCurrentTestName(), "sshd@apache.org").call();
                    git.push().call();
                    assertTrue(client.isStarted(), "Client not started after 1st push");

                    Path readmeFile = Files.createFile(localDir.resolve("readme.txt"));
                    git.add().addFilepattern(readmeFile.getFileName().toString()).call();
                    git.commit().setMessage(getCurrentTestName()).setCommitter(getCurrentTestName(), "sshd@apache.org").call();
                    git.push().call();
                    assertTrue(client.isStarted(), "Client not started after 2nd push");

                    git.pull().setRebase(true).call();
                    assertTrue(client.isStarted(), "Client not started after rebase");

                    PropertyResolver useProtocolV2 = PropertyResolverUtils
                            .toPropertyResolver(
                                    Collections.singletonMap(GitModuleProperties.GIT_PROTOCOL_VERSION.getName(),
                                            GitProtocolConstants.VERSION_2_REQUEST));
                    client.setParentPropertyResolver(useProtocolV2);
                    git.fetch().call();
                    assertTrue(client.isStarted(),
                            "Client not started after fetch using GIT_PROTOCOL='version=2' env. variable");

                    assertTrue(packConfig.receivePackCalled, "ReceivePack was not configured");
                    assertTrue(packConfig.uploadPackCalled, "UploadPack was not configured");
                } finally {
                    client.stop();
                }

                assertFalse(client.isStarted(), "Client not stopped after exit");
            } finally {
                sshd.stop();
            }
        }
    }

    private static class GitPackTestConfig implements GitPackConfiguration {
        boolean receivePackCalled;
        boolean uploadPackCalled;

        @Override
        public void configureReceivePack(ServerSession session, ReceivePack pack) {
            receivePackCalled = true;
        }

        @Override
        public void configureUploadPack(ServerSession session, UploadPack pack) {
            uploadPackCalled = true;
        }
    }
}
