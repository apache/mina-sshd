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
package org.apache.sshd.git.pack;

import java.io.File;
import java.util.Arrays;

import com.jcraft.jsch.JSch;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.git.transport.GitSshdSessionFactory;
import org.apache.sshd.git.util.BogusPasswordAuthenticator;
import org.apache.sshd.git.util.EchoShellFactory;
import org.apache.sshd.git.util.Utils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.junit.Test;

/**
 */
public class GitPackCommandTest {

    @Test
    public void testGitPack() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(8001);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setCommandFactory(new GitPackCommandFactory("target/git/server"));
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();

        File serverDir = new File("target/git/server/test.git");
        Utils.deleteRecursive(serverDir);
        Git.init().setBare(true).setDirectory(serverDir).call();

        JSch.setConfig("StrictHostKeyChecking", "no");
        CredentialsProvider.setDefault(new UsernamePasswordCredentialsProvider("sshd", "sshd"));
        GitSshdSessionFactory.setInstance(new GitSshdSessionFactory());

        File dir = new File("target/git/local/test.git");
        Utils.deleteRecursive(dir);
        Git.cloneRepository()
                .setURI("ssh://sshd@localhost:8001/test.git")
                .setDirectory(dir)
                .call();

        Git git = Git.open(dir);
        git.commit().setMessage("First Commit").setCommitter("sshd", "sshd@apache.org").call();
        git.push().call();

        new File("target/git/local/test.git/readme.txt").createNewFile();
        git.add().addFilepattern("readme.txt").call();
        git.commit().setMessage("readme").setCommitter("sshd", "sshd@apache.org").call();
        git.push().call();

        git.pull().setRebase(true).call();

        sshd.stop();
    }

}
