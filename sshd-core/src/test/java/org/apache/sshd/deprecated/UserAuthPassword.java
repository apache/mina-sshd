/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPassword extends AbstractUserAuth {
    private final String password;

    public UserAuthPassword(ClientSession session, String service, String password) {
        super(session, service);
        this.password = password;
    }

    @Override
    public Result next(Buffer buffer) throws IOException {
        if (buffer == null) {
            log.debug("Send SSH_MSG_USERAUTH_REQUEST for password");
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            buffer.putString(session.getUsername());
            buffer.putString(service);
            buffer.putString("password");
            buffer.putBoolean(false);
            buffer.putString(password);
            session.writePacket(buffer);
            return Result.Continued;
        } else {
            int cmd = buffer.getUByte();
            if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                log.debug("Received SSH_MSG_USERAUTH_SUCCESS");
                return Result.Success;
            }
            if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                log.debug("Received SSH_MSG_USERAUTH_FAILURE");
                return Result.Failure;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Received unkown packet {}", Integer.valueOf(cmd & 0xFF));
                }
                // TODO: check packets
                return Result.Continued;
            }
        }
    }

}
