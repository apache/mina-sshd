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
import java.util.Arrays;

import com.jcraft.jsch.JSch;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.git.transport.GitSshdSessionFactory;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.Utils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
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

    @Test
    public void testGitPack() throws Exception {
        Path targetParent = detectTargetFolder().getParent();
        Path gitRootDir = getTempTargetRelativeFile(getClass().getSimpleName());

        try (SshServer sshd = setupTestServer()) {
            Path serverRootDir = gitRootDir.resolve("server");
            sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
            sshd.setCommandFactory(new GitPackCommandFactory(Utils.resolveRelativeRemotePath(targetParent, serverRootDir)));
            sshd.start();

            int port = sshd.getPort();
            try {
                Path serverDir = serverRootDir.resolve("test.git");
                Utils.deleteRecursive(serverDir);
                Git.init().setBare(true).setDirectory(serverDir.toFile()).call();

                JSch.setConfig("StrictHostKeyChecking", "no");
                CredentialsProvider.setDefault(new UsernamePasswordCredentialsProvider(getCurrentTestName(), getCurrentTestName()));
                SshSessionFactory.setInstance(new GitSshdSessionFactory());

                Path localRootDir = gitRootDir.resolve("local");
                Path localDir = localRootDir.resolve(serverDir.getFileName());
                Utils.deleteRecursive(localDir);
                Git.cloneRepository()
                        .setURI("ssh://" + getCurrentTestName() + "@" + TEST_LOCALHOST + ":" + port + "/" + serverDir.getFileName())
                        .setDirectory(localDir.toFile())
                        .call();

                Git git = Git.open(localDir.toFile());
                git.commit().setMessage("First Commit").setCommitter(getCurrentTestName(), "sshd@apache.org").call();
                git.push().call();

                Path readmeFile = Files.createFile(localDir.resolve("readme.txt"));
                git.add().addFilepattern(readmeFile.getFileName().toString()).call();
                git.commit().setMessage(getCurrentTestName()).setCommitter(getCurrentTestName(), "sshd@apache.org").call();
                git.push().call();

                git.pull().setRebase(true).call();
            } finally {
                sshd.stop();
            }
        }
    }
}
