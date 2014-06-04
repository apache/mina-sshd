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
package org.apache.sshd.git.pgm;

import java.io.File;
import java.util.Arrays;

import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.git.util.BogusPasswordAuthenticator;
import org.apache.sshd.git.util.EchoShellFactory;
import org.apache.sshd.git.util.Utils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.eclipse.jgit.api.Git;
import org.junit.Test;

/**
 */
public class GitPgmCommandTest {

    @Test
    public void testGitpgm() throws Exception {

        //
        // TODO: the GitpgmCommandFactory is kept in the test tree
        // TODO: because it's quite limited for now
        //

        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(8001);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setCommandFactory(new GitPgmCommandFactory("target/git/pgm"));
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();

        File serverDir = new File("target/git/pgm");
        Utils.deleteRecursive(serverDir);

        File repo = new File(serverDir, "test");

        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        ClientSession session = client.connect("sshd", "localhost", 8001).await().getSession();
        session.addPasswordIdentity("sshd");
        session.auth().verify();

        Git.init().setDirectory(repo).call();
        Git git = Git.open(repo);
        git.commit().setMessage("First Commit").setCommitter("sshd", "sshd@apache.org").call();

        new File("target/git/pgm/test/readme.txt").createNewFile();
        execute(session, "git --git-dir test add readme.txt");

        execute(session, "git --git-dir test commit -m \"readme\"");

        client.stop();
        sshd.stop();
    }

    private void execute(ClientSession session, String command) throws Exception {
        ChannelExec channel = session.createExecChannel(command);
        channel.setOut(System.out);
        channel.setErr(System.err);
        channel.open().verify();
        channel.waitFor(ClientChannel.CLOSED, 0);
        if (channel.getExitStatus() != null) {
            int s = channel.getExitStatus();
            if (s != 0) {
                throw new Exception("Command failed with status " + s);
            }
        }
    }

}
