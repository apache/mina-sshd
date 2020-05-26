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

package org.apache.sshd.deprecated;

import java.io.IOException;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
// CHECKSTYLE:OFF
public class UserAuthPassword extends AbstractUserAuth {
    private final String password;

    public UserAuthPassword(ClientSession session, String service, String password) {
        super(session, service);
        this.password = password;
    }

    @Override
    public Result next(Buffer buffer) throws IOException {
        ClientSession session = getClientSession();
        String service = getService();
        boolean debugEnabled = log.isDebugEnabled();
        if (buffer == null) {
            if (debugEnabled) {
                log.debug("Send SSH_MSG_USERAUTH_REQUEST for password");
            }
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            buffer.putString(session.getUsername());
            buffer.putString(service);
            buffer.putString(UserAuthMethodFactory.PASSWORD);
            buffer.putBoolean(false);
            buffer.putString(password);
            session.writePacket(buffer);
            return Result.Continued;
        } else {
            int cmd = buffer.getUByte();
            if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                if (debugEnabled) {
                    log.debug("Received SSH_MSG_USERAUTH_SUCCESS");
                }
                return Result.Success;
            }
            if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                String methods = buffer.getString();
                boolean partial = buffer.getBoolean();
                if (debugEnabled) {
                    log.debug("Received SSH_MSG_USERAUTH_FAILURE - partial={}, methods={}", partial, methods);
                }
                return Result.Failure;
            } else {
                if (debugEnabled) {
                    log.debug("Received unknown packet {}", cmd & 0xFF);
                }
                // TODO: check packets
                return Result.Continued;
            }
        }
    }
}
// CHECKSTYLE:ON
