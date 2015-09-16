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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Manages a &quot;keyboard-interactive&quot; exchange according to
 * <A HREF="https://www.ietf.org/rfc/rfc4256.txt">RFC4256</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthKeyboardInteractive extends AbstractUserAuth {

    private Iterator<String> passwords;
    private String current;
    private int nbTrials;
    private int maxTrials;

    public UserAuthKeyboardInteractive() {
        super();
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
        passwords = pwds.iterator();
        maxTrials = session.getIntProperty(ClientFactoryManager.PASSWORD_PROMPTS, ClientFactoryManager.DEFAULT_PASSWORD_PROMPTS);
    }

    @Override
    public boolean process(Buffer buffer) throws Exception {
        ClientSession session = getClientSession();
        String username = session.getUsername();
        String service = getService();

        if (buffer == null) {
            if (passwords.hasNext()) {
                current = passwords.next();
            } else if (nbTrials++ < maxTrials) {
                current = null;
            } else {
                return false;
            }

            if (log.isDebugEnabled()) {
                log.debug("process({}@{})[{}] Send SSH_MSG_USERAUTH_REQUEST for keyboard-interactive",
                          username, session, service);
            }
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                                username.length() + service.length() + UserAuthKeyboardInteractiveFactory.NAME.length() + Integer.SIZE);
            buffer.putString(username);
            buffer.putString(service);
            buffer.putString(UserAuthKeyboardInteractiveFactory.NAME);
            buffer.putString("");
            buffer.putString("");
            session.writePacket(buffer);
            return true;
        }

        int cmd = buffer.getUByte();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST) {
            if (log.isDebugEnabled()) {
                log.debug("process({}@{})[{}] Received SSH_MSG_USERAUTH_INFO_REQUEST for keyboard-interactive",
                          username, session, service);
            }

            String name = buffer.getString();
            String instruction = buffer.getString();
            String language_tag = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("process({}@{})[{}] SSH_MSG_USERAUTH_INFO_REQUEST name={} instruction={} language={}",
                          username, session, service, name, instruction, language_tag);
            }

            int num = buffer.getInt();
            String[] prompt = new String[num];
            boolean[] echo = new boolean[num];
            for (int i = 0; i < num; i++) {
                // according to RFC4256: "The prompt field(s) MUST NOT be empty strings."
                prompt[i] = buffer.getString();
                echo[i] = buffer.getBoolean();
            }

            if (log.isTraceEnabled()) {
                log.trace("process({}@{})[{}] Prompt: {}", username, session, service, Arrays.toString(prompt));
                log.trace("process({}@{})[{}] Echo: {}", username, session, service, Arrays.toString(echo));
            }

            String[] rep = getUserResponses(name, instruction, language_tag, prompt, echo);
            if (rep == null) {
                return false;
            }

            /*
             * According to RFC4256:
             *
             *      If the num-responses field does not match the num-prompts
             *      field in the request message, the server MUST send a failure
             *      message.
             *
             * However it is the server's (!) responsibility to fail, so we only warn...
             */
            if (num != rep.length) {
                log.warn("process({}@{}) Mismatched prompts ({}) vs. responses count ({})",
                         username, session, num, rep.length);
            }

            buffer = session.prepareBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE, BufferUtils.clear(buffer));
            buffer.putInt(rep.length);
            for (String r : rep) {
                buffer.putString(r);
            }
            session.writePacket(buffer);
            return true;
        }
        throw new IllegalStateException("process(" + username + "@" + session + ")[" + service + ") received unknown packet: cmd=" + cmd);
    }

    protected String getCurrentPasswordCandidate() {
        return current;
    }

    /**
     * @param name        The interaction name - may be empty
     * @param instruction The instruction - may be empty
     * @param lang        The language tag - may be empty
     * @param prompt      The prompts - may be empty
     * @param echo        Whether to echo the response for the prompt or not - same
     *                    length as the prompts
     * @return The response for each prompt - if {@code null} then the assumption
     * is that some internal error occurred and no response is sent. <B>Note:</B>
     * according to <A HREF="https://www.ietf.org/rfc/rfc4256.txt">RFC4256</A>
     * the number of responses should be <U>exactly</U> the same as the number
     * of prompts. However, since it is the <U>server's</U> responsibility to
     * enforce this we do not validate the response (other than logging it as
     * a warning...)
     */
    protected String[] getUserResponses(String name, String instruction, String lang, String[] prompt, boolean[] echo) {
        int num = GenericUtils.length(prompt);
        if (num == 0) {
            return GenericUtils.EMPTY_STRING_ARRAY;
        }

        String candidate = getCurrentPasswordCandidate();
        if (useCurrentPassword(candidate, name, instruction, lang, prompt, echo)) {
            return new String[]{candidate};
        } else {
            ClientSession session = getClientSession();
            UserInteraction ui = UserInteraction.Utils.resolveUserInteraction(session);
            if (ui != null) {
                return ui.interactive(session, name, instruction, lang, prompt, echo);
            }
        }

        return null;
    }

    protected boolean useCurrentPassword(String password, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
        int num = GenericUtils.length(prompt);
        if ((num != 1) || (password == null) || echo[0]) {
            return false;
        }

        // check that prompt is something like "XXX password YYY:"
        String value = prompt[0].toLowerCase();
        int passPos = value.lastIndexOf("password");
        if (passPos < 0) {  // no password keyword in prompt
            return false;
        }

        int sepPos = value.lastIndexOf(':');
        if (sepPos <= passPos) {    // no prompt separator or separator before the password keyword
            return false;
        }

        return true;
    }

    @Override
    public void destroy() {
        // nothing
    }
}
