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
package org.apache.sshd.git;

import java.util.Arrays;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.git.util.BogusPasswordAuthenticator;
import org.apache.sshd.git.util.EchoShellFactory;
import org.apache.sshd.git.util.Utils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.junit.Ignore;
import org.junit.Test;

/**
 */
public class GitServerTest {

    @Test
    @Ignore
    public void testGit() {

    }

    public static void main(String[] args) throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.getProperties().put(SshServer.IDLE_TIMEOUT, "10000");
        sshd.setPort(8001);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setShellFactory(new EchoShellFactory());
//        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setCommandFactory(new CommandFactory() {
            public Command createCommand(String command) {
                if (command.startsWith("git-")) {
                    return new GitCommand(command.substring("git-".length()));
                } else {
                    return new UnknownCommand(command);
                }
            }
        });
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        Thread.sleep(100000);
    }

}
