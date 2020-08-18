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

import java.util.List;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * Provides a default implementation for {@link KeyboardInteractiveAuthenticator} where it prompts for the password.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultKeyboardInteractiveAuthenticator
        extends AbstractLoggingBean
        implements KeyboardInteractiveAuthenticator {

    public static final DefaultKeyboardInteractiveAuthenticator INSTANCE = new DefaultKeyboardInteractiveAuthenticator();

    public DefaultKeyboardInteractiveAuthenticator() {
        super();
    }

    @Override
    public InteractiveChallenge generateChallenge(
            ServerSession session, String username, String lang, String subMethods)
            throws Exception {
        PasswordAuthenticator auth = session.getPasswordAuthenticator();
        if (auth == null) {
            if (log.isDebugEnabled()) {
                log.debug("generateChallenge({})[{}] no password authenticator", session, username);
            }
            return null;
        }

        InteractiveChallenge challenge = new InteractiveChallenge();
        challenge.setInteractionName(getInteractionName(session));
        challenge.setInteractionInstruction(getInteractionInstruction(session));
        challenge.setLanguageTag(getInteractionLanguage(session));
        challenge.addPrompt(getInteractionPrompt(session), isInteractionPromptEchoEnabled(session));
        return challenge;
    }

    @Override
    public boolean authenticate(ServerSession session, String username, List<String> responses) throws Exception {
        PasswordAuthenticator auth = session.getPasswordAuthenticator();
        if (auth == null) {
            if (log.isDebugEnabled()) {
                log.debug("authenticate({})[{}] no password authenticator", session, username);
            }
            return false;
        }

        int numResp = GenericUtils.size(responses);
        if (numResp != 1) {
            throw new SshException("Mismatched number of responses");
        }

        try {
            return auth.authenticate(username, responses.get(0), session);
        } catch (Error e) {
            warn("authenticate({})[{}] failed ({}) to consult password authenticator: {}",
                    session, username, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }
    }

    protected String getInteractionName(ServerSession session) {
        return CoreModuleProperties.KB_SERVER_INTERACTIVE_NAME.getRequired(session);
    }

    protected String getInteractionInstruction(ServerSession session) {
        return CoreModuleProperties.KB_SERVER_INTERACTIVE_INSTRUCTION.getRequired(session);
    }

    protected String getInteractionLanguage(ServerSession session) {
        return CoreModuleProperties.KB_SERVER_INTERACTIVE_LANG.getRequired(session);
    }

    protected String getInteractionPrompt(ServerSession session) {
        return CoreModuleProperties.KB_SERVER_INTERACTIVE_PROMPT.getRequired(session);
    }

    protected boolean isInteractionPromptEchoEnabled(ServerSession session) {
        return CoreModuleProperties.KB_SERVER_INTERACTIVE_ECHO_PROMPT.getRequired(session);
    }
}
