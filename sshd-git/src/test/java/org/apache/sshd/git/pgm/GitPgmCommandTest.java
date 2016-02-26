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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.Utils;
import org.eclipse.jgit.api.Git;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GitPgmCommandTest extends BaseTestSupport {
    public GitPgmCommandTest() {
        super();
    }

    @Test
    public void testGitPgm() throws Exception {
        Path targetParent = detectTargetFolder().getParent();
        Path serverDir = getTempTargetRelativeFile(getClass().getSimpleName());

        //
        // TODO: the GitpgmCommandFactory is kept in the test tree
        // TODO: because it's quite limited for now
        //

        try (SshServer sshd = setupTestServer()) {
            sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
            sshd.setCommandFactory(new GitPgmCommandFactory(Utils.resolveRelativeRemotePath(targetParent, serverDir)));
            sshd.start();

            int port = sshd.getPort();
            try {
                Utils.deleteRecursive(serverDir);

                try (SshClient client = setupTestClient()) {
                    client.start();

                    try (ClientSession session = client.connect(getCurrentTestName(), SshdSocketAddress.LOCALHOST_IP, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                        session.addPasswordIdentity(getCurrentTestName());
                        session.auth().verify(5L, TimeUnit.SECONDS);

                        Path repo = serverDir.resolve(getCurrentTestName());
                        Git.init().setDirectory(repo.toFile()).call();
                        Git git = Git.open(repo.toFile());
                        git.commit().setMessage("First Commit").setCommitter(getCurrentTestName(), "sshd@apache.org").call();

                        Path readmeFile = Files.createFile(repo.resolve("readme.txt"));
                        String commandPrefix = "git --git-dir " + repo.getFileName();
                        execute(session, commandPrefix + " add " + readmeFile.getFileName());
                        execute(session, commandPrefix + " commit -m \"readme\"");
                    } finally {
                        client.stop();
                    }
                }
            } finally {
                sshd.stop();
            }
        }
    }

    private void execute(ClientSession session, String command) throws Exception {
        try (ChannelExec channel = session.createExecChannel(command)) {
            channel.setOut(System.out);
            channel.setErr(System.err);
            channel.open().verify(11L, TimeUnit.SECONDS);

            Collection<ClientChannelEvent> result =
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.MINUTES.toMillis(1L));
            assertTrue("Command '" + command + "'not completed on time: " + result, result.contains(ClientChannelEvent.CLOSED));

            Integer status = channel.getExitStatus();
            if (status != null) {
                assertEquals("Failed (" + status + ") " + command, 0, status.intValue());
            }
        }
    }
}
