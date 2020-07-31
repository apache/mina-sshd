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
package org.apache.sshd.server.auth;

import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.util.test.JSchLogger;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AsyncAuthInteractiveTest extends AsyncAuthTestBase {
    public AsyncAuthInteractiveTest() {
        super();
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Override
    protected boolean authenticate() throws Exception {
        JSch jsch = new JSch();
        Session session = jsch.getSession("whatever", "localhost", port);
        session.setUserInfo(new UserInfo() {
            @Override
            public String getPassphrase() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String getPassword() {
                return "whocares";
            }

            @Override
            public boolean promptPassword(String s) {
                return true;
            }

            @Override
            public boolean promptPassphrase(String s) {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean promptYesNo(String s) {
                return true;
            }

            @Override
            public void showMessage(String s) {
                // Do nothing
            }
        });
        try {
            session.connect();
        } catch (JSchException e) {
            String reason = e.getMessage();
            switch (reason) {
                case "Auth cancel":
                case "Auth fail":
                    return false;
                default:
                    throw e;
            }
        }

        try {
            ChannelShell channel = (ChannelShell) session.openChannel(Channel.CHANNEL_SHELL);
            channel.connect();

            try {
                channel.disconnect();
            } catch (Exception ignore) {
                // ignore
            }
        } finally {
            try {
                session.disconnect();
            } catch (Exception ignore) {
                // ignore
            }
        }

        return true;
    }
}
