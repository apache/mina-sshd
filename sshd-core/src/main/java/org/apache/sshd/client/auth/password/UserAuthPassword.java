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
package org.apache.sshd.client.auth.password;

import java.io.IOException;
import java.util.Iterator;
import java.util.Objects;

import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Implements the &quot;password&quot; authentication mechanism
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
    public void init(ClientSession session, String service) throws Exception {
        super.init(session, service);
        passwords = ClientSession.passwordIteratorOf(session);
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        if ((passwords == null) || (!passwords.hasNext())) {
            if (log.isDebugEnabled()) {
                log.debug("sendAuthDataRequest({})[{}] no more passwords to send", session, service);
            }

            return false;
        }

        current = passwords.next();
        String username = session.getUsername();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                username.length() + service.length() + getName().length() + current.length() + Integer.SIZE);
        sendPassword(buffer, session, current, current);
        return true;
    }

    @Override
    protected boolean processAuthDataRequest(ClientSession session, String service, Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
            throw new IllegalStateException("processAuthDataRequest(" + session + ")[" + service + "]"
                            + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
        }

        String prompt = buffer.getString();
        String lang = buffer.getString();
        UserInteraction ui = session.getUserInteraction();
        boolean interactive;
        String password;
        boolean debugEnabled = log.isDebugEnabled();
        try {
            interactive = (ui != null) && ui.isInteractionAllowed(session);
            password = interactive ? ui.getUpdatedPassword(session, prompt, lang) : null;
        } catch (Error e) {
            log.warn("processAuthDataRequest({})[{}] failed ({}) to consult interaction: {}",
                 session, service, e.getClass().getSimpleName(), e.getMessage());
            if (debugEnabled) {
                log.debug("processAuthDataRequest(" + session + ")[" + service + "] interaction consultation failure details", e);
            }

            throw new RuntimeSshException(e);
        }

        if (interactive) {
            if (GenericUtils.isEmpty(password)) {
                if (debugEnabled) {
                    log.debug("processAuthDataRequest({})[{}] No updated password for prompt={}, lang={}",
                          session, service, prompt, lang);
                }
                return false;
            } else {
                sendPassword(buffer, session, password, password);
                return true;
            }
        }

        if (debugEnabled) {
            log.debug("processAuthDataRequest({})[{}] no UI for password change request for prompt={}, lang={}",
                  session, service, prompt, lang);
        }

        return false;
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
     * @return An {@link IoWriteFuture} that can be used to wait and check
     * on the success/failure of the request packet being sent
     * @throws IOException If failed to send the message.
     */
    protected IoWriteFuture sendPassword(Buffer buffer, ClientSession session, String oldPassword, String newPassword) throws IOException {
        String username = session.getUsername();
        String service = getService();
        String name = getName();
        boolean modified = !Objects.equals(oldPassword, newPassword);
        if (log.isDebugEnabled()) {
            log.debug("sendPassword({})[{}] send SSH_MSG_USERAUTH_REQUEST for {} - modified={}",
                      session, service, name, modified);
        }

        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                GenericUtils.length(username) + GenericUtils.length(service)
              + GenericUtils.length(name) + GenericUtils.length(oldPassword)
              + (modified ? GenericUtils.length(newPassword) : 0) + Long.SIZE);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(modified);
        // see RFC-4252 section 8
        buffer.putString(oldPassword);
        if (modified) {
            buffer.putString(newPassword);
        }

        return session.writePacket(buffer);
    }
}
