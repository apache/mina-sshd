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
 * Issue a &quot;keyboard-interactive&quot; command according to
 * <A HREF="https://tools.ietf.org/html/rfc4256">RFC4256</A>
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
            return doInitialAuth(session, username, auth, buffer);
        } else {
            return doValidateAuthResponse(session, username, auth, buffer);
        }
    }

    protected Boolean doInitialAuth(
            ServerSession session, String username, KeyboardInteractiveAuthenticator auth, Buffer buffer)
            throws Exception {
        String lang = buffer.getString();
        String subMethods = buffer.getString();
        boolean debugEnabled = log.isDebugEnabled();
        if (auth == null) {
            if (debugEnabled) {
                log.debug("doAuth({}@{})[methods={}, lang={}] - no interactive authenticator to generate challenge",
                        username, session, subMethods, lang);
            }
            return false;
        }

        InteractiveChallenge challenge;
        try {
            challenge = auth.generateChallenge(session, username, lang, subMethods);
        } catch (Error e) {
            warn("doAuth({}@{}) failed ({}) to generate authenticator challenge: {}",
                    username, session, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        if (challenge == null) {
            if (debugEnabled) {
                log.debug("doAuth({}@{})[methods={}, lang={}] - no interactive challenge generated",
                        username, session, subMethods, lang);
            }
            return false;
        }

        if (debugEnabled) {
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
    }

    protected Boolean doValidateAuthResponse(
            ServerSession session, String username, KeyboardInteractiveAuthenticator auth, Buffer buffer)
            throws Exception {
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE) {
            throw new SshException("Received unexpected message: " + SshConstants.getCommandMessageName(cmd));
        }

        int num = buffer.getInt();
        // Protect against malicious or corrupted packets
        if ((num < 0) || (num > SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
            log.error("doValidateAuthResponse({}@{}) illogical response count: {}", username, session, num);
            throw new IndexOutOfBoundsException("Illogical response count: " + num);
        }

        List<String> responses = (num <= 0) ? Collections.emptyList() : new ArrayList<>(num);
        boolean traceEnabled = log.isTraceEnabled();
        for (int index = 1; index <= num; index++) {
            String value = buffer.getString();
            if (traceEnabled) {
                log.trace("doAuth({}@{}) response {}/{}: {}", username, session, index, num, value);
            }
            responses.add(value);
        }

        boolean debugEnabled = log.isDebugEnabled();
        if (auth == null) {
            if (debugEnabled) {
                log.debug("doAuth({}@{}) no interactive authenticator to validate {} responses",
                        username, session, num);
            }
            return false;
        }

        boolean authed;
        try {
            authed = auth.authenticate(session, username, responses);
        } catch (Error e) {
            warn("doAuth({}@{}) failed ({}) to consult authenticator: {}",
                    username, session, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        if (debugEnabled) {
            log.debug("doAuth({}@{}) authenticate {} responses result: {}",
                    username, session, num, authed);
        }

        return authed;
    }
}
