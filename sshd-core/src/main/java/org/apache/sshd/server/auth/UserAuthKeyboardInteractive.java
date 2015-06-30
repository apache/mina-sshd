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
package org.apache.sshd.server.auth;

import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * Issue a &quot;keyboard-interactive&quot; command according to <A HREF="https://www.ietf.org/rfc/rfc4256.txt">RFC4256</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthKeyboardInteractive extends AbstractUserAuth {
    // configuration parameters on the FactoryManager to configure the message values
    public static final String KB_INTERACTIVE_NAME_PROP = "kb-interactive-name";
        public static final String DEFAULT_KB_INTERACTIVE_NAME = "Password authentication";
    public static final String KB_INTERACTIVE_INSTRUCTION_PROP = "kb-interactive-instruction";
        public static final String DEFAULT_KB_INTERACTIVE_INSTRUCTION = "";
    public static final String KB_INTERACTIVE_LANG_PROP = "kb-interactive-language";
        public static final String DEFAULT_KB_INTERACTIVE_LANG = "en-US";
    public static final String KB_INTERACTIVE_PROMPT_PROP = "kb-interactive-prompt";
        public static final String DEFAULT_KB_INTERACTIVE_PROMPT = "Password: ";
    public static final String KB_INTERACTIVE_ECHO_PROMPT_PROP = "kb-interactive-echo-prompt";
        public static final boolean DEFAULT_KB_INTERACTIVE_ECHO_PROMPT = false;

    public UserAuthKeyboardInteractive() {
        super();
    }

    @Override
    protected Boolean doAuth(Buffer buffer, boolean init) throws Exception {
        if (init) {
            // Prompt for password
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST);
            buffer.putString(getInteractionName());
            buffer.putString(getInteractionInstruction());
            buffer.putString(getInteractionLanguage());
            buffer.putInt(1);
            buffer.putString(getInteractionPrompt());
            buffer.putBoolean(isInteractionPromptEchoEnabled());
            session.writePacket(buffer);
            return null;
        } else {
            byte cmd = buffer.getByte();
            if (cmd != SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE) {
                throw new SshException("Received unexpected message: " + cmd);
            }
            int num = buffer.getInt();
            /*
             * According to RFC4256:
             * 
             *      If the num-responses field does not match the num-prompts
             *      field in the request message, the server MUST send a failure
             *      message.
             */
            if (num != 1) {
                throw new SshException("Expected 1 response from user but received " + num);
            }
            String password = buffer.getString();
            return Boolean.valueOf(checkPassword(session, username, password));
        }
    }

    protected String getInteractionName() {
        return FactoryManagerUtils.getStringProperty(session, KB_INTERACTIVE_NAME_PROP, DEFAULT_KB_INTERACTIVE_NAME);
    }

    protected String getInteractionInstruction() {
        return FactoryManagerUtils.getStringProperty(session, KB_INTERACTIVE_INSTRUCTION_PROP, DEFAULT_KB_INTERACTIVE_INSTRUCTION);
    }

    protected String getInteractionLanguage() {
        return FactoryManagerUtils.getStringProperty(session, KB_INTERACTIVE_LANG_PROP, DEFAULT_KB_INTERACTIVE_LANG);
    }

    protected String getInteractionPrompt() {
        return FactoryManagerUtils.getStringProperty(session, KB_INTERACTIVE_PROMPT_PROP, DEFAULT_KB_INTERACTIVE_PROMPT);
    }

    protected boolean isInteractionPromptEchoEnabled() {
        return FactoryManagerUtils.getBooleanProperty(session, KB_INTERACTIVE_ECHO_PROMPT_PROP, DEFAULT_KB_INTERACTIVE_ECHO_PROMPT);
    }

    protected boolean checkPassword(ServerSession session, String username, String password) throws Exception {
        ServerFactoryManager manager = session.getFactoryManager();
        PasswordAuthenticator auth = ValidateUtils.checkNotNull(
                manager.getPasswordAuthenticator(),
                "No PasswordAuthenticator configured",
                GenericUtils.EMPTY_BYTE_ARRAY);
        return auth.authenticate(username, password, session);
    }
}
