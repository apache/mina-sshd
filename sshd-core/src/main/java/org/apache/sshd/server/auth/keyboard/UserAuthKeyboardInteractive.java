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
package org.apache.sshd.server.auth.keyboard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.auth.AbstractUserAuth;
import org.apache.sshd.server.session.ServerSession;

/**
 * Issue a &quot;keyboard-interactive&quot; command according to <A HREF="https://www.ietf.org/rfc/rfc4256.txt">RFC4256</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthKeyboardInteractive extends AbstractUserAuth {
    public static final String NAME = UserAuthKeyboardInteractiveFactory.NAME;

    public UserAuthKeyboardInteractive() {
        super(NAME);
    }

    @Override
    protected Boolean doAuth(Buffer buffer, boolean init) throws Exception {
        ServerSession session = getServerSession();
        String username = getUsername();
        KeyboardInteractiveAuthenticator auth = session.getKeyboardInteractiveAuthenticator();
        if (init) {
            String lang = buffer.getString();
            String subMethods = buffer.getString();
            if (auth == null) {
                if (log.isDebugEnabled()) {
                    log.debug("doAuth({}@{})[methods={}, lang={}] - no interactive authenticator to generate challenge",
                              username, session, subMethods, lang);
                }
                return false;
            }

            InteractiveChallenge challenge;
            try {
                challenge = auth.generateChallenge(session, username, lang, subMethods);
            } catch (Error e) {
                log.warn("doAuth({}@{}) failed ({}) to generate authenticator challenge: {}",
                         username, session, e.getClass().getSimpleName(), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doAuth(" + username + "@" + session + ") authenticator challenge failure details", e);
                }
                throw new RuntimeSshException(e);
            }

            if (challenge == null) {
                if (log.isDebugEnabled()) {
                    log.debug("doAuth({}@{})[methods={}, lang={}] - no interactive challenge generated",
                              username, session, subMethods, lang);
                }
                return false;
            }

            if (log.isDebugEnabled()) {
                log.debug("doAuth({}@{})[methods={}, lang={}] challenge name={}, instruction={}, lang={}, num. prompts={}",
                          username, session, subMethods, lang,
                          challenge.getInteractionName(), challenge.getInteractionInstruction(),
                          challenge.getLanguageTag(), GenericUtils.size(challenge.getPrompts()));
            }

            // Prompt for password
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST);
            challenge.append(buffer);
            session.writePacket(buffer);
            return null;
        } else {
            int cmd = buffer.getUByte();
            if (cmd != SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE) {
                throw new SshException("Received unexpected message: " + SshConstants.getCommandMessageName(cmd));
            }

            int num = buffer.getInt();
            List<String> responses = (num <= 0) ? Collections.<String>emptyList() : new ArrayList<String>(num);
            for (int index = 0; index < num; index++) {
                String value = buffer.getString();
                if (log.isTraceEnabled()) {
                    log.trace("doAuth({}@{}) response #{}: {}", username, session, index + 1, value);
                }
                responses.add(value);
            }

            if (auth == null) {
                if (log.isDebugEnabled()) {
                    log.debug("doAuth({}@{}) no interactive authenticator to validate {} responses",
                              username, session, num);
                }
                return false;
            }

            boolean authed;
            try {
                authed = auth.authenticate(session, username, responses);
            } catch (Error e) {
                log.warn("doAuth({}@{}) failed ({}) to consult authenticator: {}",
                         username, session, e.getClass().getSimpleName(), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doAuth(" + username + "@" + session + ") authenticator consultation failure details", e);
                }
                throw new RuntimeSshException(e);
            }

            if (log.isDebugEnabled()) {
                log.debug("doAuth({}@{}) authenticate {} responses result: {}",
                          username, session, num, authed);
            }

            return authed;
        }
    }
}
