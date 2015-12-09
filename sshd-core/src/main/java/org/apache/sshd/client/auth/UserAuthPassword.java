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
package org.apache.sshd.client.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPassword extends AbstractUserAuth {
    public static final String NAME = UserAuthPasswordFactory.NAME;

    private Iterator<String> passwords;
    private String current;

    public UserAuthPassword() {
        super(NAME);
    }

    @Override
    public void init(ClientSession session, String service, Collection<?> identities) throws Exception {
        super.init(session, service, identities);

        List<String> pwds = new ArrayList<>();
        for (Object o : identities) {
            if (o instanceof String) {
                pwds.add((String) o);
            }
        }
        this.passwords = pwds.iterator();
    }

    @Override
    public boolean process(Buffer buffer) throws Exception {
        ClientSession session = getClientSession();
        String username = session.getUsername();
        String service = getService();

        // Send next password
        if (buffer == null) {
            if (passwords.hasNext()) {
                current = passwords.next();
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                                    username.length() + service.length() + getName().length() + current.length() + Integer.SIZE);
                sendPassword(buffer, session, current, current);
                return true;
            }

            if (log.isDebugEnabled()) {
                log.debug("process({}@{})[{}] no more passwords to send", username, session, service);
            }

            return false;
        }

        int cmd = buffer.getUByte();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
            String prompt = buffer.getString();
            String lang = buffer.getString();
            UserInteraction ui = session.getUserInteraction();
            if ((ui != null) && ui.isInteractionAllowed(session)) {
                String password = ui.getUpdatedPassword(session, prompt, lang);
                if (GenericUtils.isEmpty(password)) {
                    if (log.isDebugEnabled()) {
                        log.debug("process({}@{})[{}] No updated password for prompt={}, lang={}",
                                  username, session, service, prompt, lang);
                    }
                } else {
                    sendPassword(buffer, session, password, password);
                    return true;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("process({}@{})[{}] no UI for password change request for prompt={}, lang={}",
                              username, session, service, prompt, lang);
                }
            }

            return false;
        }

        throw new IllegalStateException("process(" + username + "@" + session + ")[" + service + "]"
                + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
    }

    /**
     * Sends the password via a {@code SSH_MSG_USERAUTH_REQUEST} message.
     * If old and new password are not the same then it requests a password
     * modification from the server (which may be denied if the server does
     * not support this feature).
     *
     * @param buffer The {@link Buffer} to re-use for sending the message
     * @param session The target {@link ClientSession}
     * @param oldPassword The previous password
     * @param newPassword The new password
     * @throws IOException If failed to send the message.
     */
    protected void sendPassword(Buffer buffer, ClientSession session, String oldPassword, String newPassword) throws IOException {
        String username = session.getUsername();
        String service = getService();
        String name = getName();
        boolean modified = !Objects.equals(oldPassword, newPassword);
        if (log.isDebugEnabled()) {
            log.debug("sendPassword({}@{})[{}] send SSH_MSG_USERAUTH_REQUEST for {} - modified={}",
                      username, session, service, name, modified);
        }

        buffer = session.prepareBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST, BufferUtils.clear(buffer));
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(modified);
        // see RFC-4252 section 8
        buffer.putString(oldPassword);
        if (modified) {
            buffer.putString(newPassword);
        }
        session.writePacket(buffer);
    }

    @Override
    public void destroy() {
        // ignored
    }
}
