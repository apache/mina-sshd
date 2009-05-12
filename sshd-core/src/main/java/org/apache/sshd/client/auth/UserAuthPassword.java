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
package org.apache.sshd.client.auth;

import java.io.IOException;

import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPassword implements UserAuth {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    public UserAuthPassword(ClientSessionImpl session, String username, String password) throws IOException {
        log.info("Send SSH_MSG_USERAUTH_REQUEST for password");
        Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(username);
        buffer.putString("ssh-connection");
        buffer.putString("password");
        buffer.putByte((byte) 0);
        buffer.putString(password);
        session.writePacket(buffer);
    }

    public Result next(Buffer buffer) throws IOException {
        SshConstants.Message cmd = buffer.getCommand();
        log.info("Received {}", cmd);
        if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_SUCCESS) {
            return Result.Success;
        } if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_FAILURE) {
            return Result.Failure;
        } else {
            // TODO: check packets
            return Result.Continued;
        }
    }

}
