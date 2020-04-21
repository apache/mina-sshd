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
import java.util.Arrays;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Userauth with keyboard-interactive method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:j.kapitza@schwarze-allianz.de">Jens Kapitza</a>
 */
// CHECKSTYLE:OFF
public class UserAuthKeyboardInteractive extends AbstractUserAuth {

    private final String password;

    public UserAuthKeyboardInteractive(ClientSession session, String service, String password) {
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
            buffer.putString("keyboard-interactive");
            buffer.putString("");
            buffer.putString("");
            session.writePacket(buffer);
            return Result.Continued;
        } else {
            int cmd = buffer.getUByte();
            switch (cmd) {
                case SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST: {
                    String name = buffer.getString();
                    String instruction = buffer.getString();
                    String language_tag = buffer.getString();
                    if (debugEnabled) {
                        log.debug("next({}) Received SSH_MSG_USERAUTH_INFO_REQUEST - name={}, instruction={}, lang={}",
                             session, name, instruction, language_tag);
                    }
                    int num = buffer.getInt();
                    // Protect against malicious or corrupted packets
                    if ((num < 0) || (num > SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
                        log.error("next({}) illogical challenges count ({}) for name={}, instruction={}",
                            session, num, name, instruction);
                        throw new IndexOutOfBoundsException("Illogical challenges count: " + num);
                    }

                    String[] prompt = (num <= 0) ? GenericUtils.EMPTY_STRING_ARRAY : new String[num];
                    boolean[] echo = (num <= 0) ? GenericUtils.EMPTY_BOOLEAN_ARRAY : new boolean[num];
                    for (int i = 0; i < num; i++) {
                        prompt[i] = buffer.getString();
                        echo[i] = buffer.getBoolean();
                    }
                    if (debugEnabled) {
                        log.debug("Promt: {}", Arrays.toString(prompt));
                        log.debug("Echo: {}", echo);
                    }

                    String[] rep = null;
                    if (num == 0) {
                        rep = GenericUtils.EMPTY_STRING_ARRAY;
                    } else if ((num == 1) && (password != null) && (!echo[0])
                            && prompt[0].toLowerCase().startsWith("password:")) {
                        rep = new String[]{password};
                    } else {
                        UserInteraction ui = session.getUserInteraction();
                        if ((ui != null) && ui.isInteractionAllowed(session)) {
                            rep = ui.interactive(session, name, instruction, language_tag, prompt, echo);
                        }
                    }
                    if (rep == null) {
                        return Result.Failure;
                    }

                    buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE);
                    buffer.putInt(rep.length);
                    for (String r : rep) {
                        buffer.putString(r);
                    }
                    session.writePacket(buffer);
                    return Result.Continued;
                }
                case SshConstants.SSH_MSG_USERAUTH_SUCCESS:
                    if (debugEnabled) {
                        log.debug("Received SSH_MSG_USERAUTH_SUCCESS");
                    }
                    return Result.Success;
                case SshConstants.SSH_MSG_USERAUTH_FAILURE:
                    {
                        String methods = buffer.getString();
                        boolean partial = buffer.getBoolean();
                        if (debugEnabled) {
                            log.debug("Received SSH_MSG_USERAUTH_FAILURE - partial={}, methods={}", partial, methods);
                        }
                        return Result.Failure;
                    }
                default:
                    if (debugEnabled) {
                        log.debug("Received unknown packet {}", cmd);
                    }
                    return Result.Continued;
            }
        }
    }
}
// CHECKSTYLE:ON
