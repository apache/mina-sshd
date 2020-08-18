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
package org.apache.sshd.client.auth.keyboard;

import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Manages a &quot;keyboard-interactive&quot; exchange according to
 * <A HREF="https://tools.ietf.org/html/rfc4256">RFC4256</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthKeyboardInteractive extends AbstractUserAuth {
    public static final String NAME = UserAuthKeyboardInteractiveFactory.NAME;

    private final AtomicBoolean requestPending = new AtomicBoolean(false);
    private final AtomicInteger trialsCount = new AtomicInteger(0);
    private final AtomicInteger emptyCount = new AtomicInteger(0);
    private Iterator<String> passwords;
    private int maxTrials;

    public UserAuthKeyboardInteractive() {
        super(NAME);
    }

    @Override
    public void init(ClientSession session, String service) throws Exception {
        super.init(session, service);
        passwords = ClientSession.passwordIteratorOf(session);
        maxTrials = CoreModuleProperties.PASSWORD_PROMPTS.getRequired(session);
        ValidateUtils.checkTrue(maxTrials > 0, "Non-positive max. trials: %d", maxTrials);
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        String name = getName();
        boolean debugEnabled = log.isDebugEnabled();
        if (requestPending.get()) {
            if (debugEnabled) {
                log.debug("sendAuthDataRequest({})[{}] no reply for previous request for {}",
                        session, service, name);
            }
            return false;
        }

        if (!verifyTrialsCount(session, service, SshConstants.SSH_MSG_USERAUTH_REQUEST, trialsCount.get(), maxTrials)) {
            return false;
        }

        String username = session.getUsername();
        String lang = getExchangeLanguageTag(session);
        String subMethods = getExchangeSubMethods(session);
        if (debugEnabled) {
            log.debug("sendAuthDataRequest({})[{}] send SSH_MSG_USERAUTH_REQUEST for {}: lang={}, methods={}",
                    session, service, name, lang, subMethods);
        }

        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                username.length() + service.length() + name.length()
                                                                                    + GenericUtils.length(lang)
                                                                                    + GenericUtils.length(subMethods)
                                                                                    + Long.SIZE /*
                                                                                                 * a bit extra for the
                                                                                                 * lengths
                                                                                                 */);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString(name);
        buffer.putString(lang);
        buffer.putString(subMethods);
        requestPending.set(true);
        session.writePacket(buffer);
        return true;
    }

    @Override
    protected boolean processAuthDataRequest(ClientSession session, String service, Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST) {
            throw new IllegalStateException(
                    "processAuthDataRequest(" + session + ")[" + service + "]"
                                            + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
        }

        requestPending.set(false);

        String name = buffer.getString();
        String instruction = buffer.getString();
        String lang = buffer.getString();
        int num = buffer.getInt();
        // Protect against malicious or corrupted packets
        if ((num < 0) || (num > SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
            log.error("processAuthDataRequest({})[{}] illogical challenges count ({}) for name={}, instruction={}",
                    session, service, num, name, instruction);
            throw new IndexOutOfBoundsException("Illogical challenges count: " + num);
        }

        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug(
                    "processAuthDataRequest({})[{}] SSH_MSG_USERAUTH_INFO_REQUEST name={}, instruction={}, language={}, num-prompts={}",
                    session, service, name, instruction, lang, num);
        }

        // SSHD-866
        int retriesCount = (num > 0) ? trialsCount.incrementAndGet() : emptyCount.incrementAndGet();
        if (!verifyTrialsCount(session, service, cmd, retriesCount, maxTrials)) {
            return false;
        }

        String[] prompt = (num > 0) ? new String[num] : GenericUtils.EMPTY_STRING_ARRAY;
        boolean[] echo = (num > 0) ? new boolean[num] : GenericUtils.EMPTY_BOOLEAN_ARRAY;
        boolean traceEnabled = log.isTraceEnabled();
        for (int i = 0; i < num; i++) {
            // TODO according to RFC4256: "The prompt field(s) MUST NOT be empty strings."
            prompt[i] = buffer.getString();
            echo[i] = buffer.getBoolean();

            if (traceEnabled) {
                log.trace("processAuthDataRequest({})[{}]({}) {}/{}: echo={}, prompt={}",
                        session, service, name, i + 1, num, echo[i], prompt[i]);
            }
        }

        String[] rep = getUserResponses(name, instruction, lang, prompt, echo);
        if (rep == null) {
            if (debugEnabled) {
                log.debug("processAuthDataRequest({})[{}] no responses for {}", session, service, name);
            }
            return false;
        }

        /*
         * According to RFC4256:
         *
         * If the num-responses field does not match the num-prompts field in the request message, the server MUST send
         * a failure message.
         *
         * However it is the server's (!) responsibility to fail, so we only warn...
         */
        if (num != rep.length) {
            log.warn("processAuthDataRequest({})[{}] Mismatched prompts ({}) vs. responses count ({})",
                    session, service, num, rep.length);
        }

        int numResponses = rep.length;
        buffer = session.createBuffer(
                SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE, numResponses * Long.SIZE + Byte.SIZE);
        buffer.putInt(numResponses);
        for (int index = 0; index < numResponses; index++) {
            String r = rep[index];
            if (traceEnabled) {
                log.trace("processAuthDataRequest({})[{}] response #{}: {}", session, service, index + 1, r);
            }
            buffer.putString(r);
        }

        session.writePacket(buffer);
        return true;
    }

    protected String getExchangeLanguageTag(ClientSession session) {
        return CoreModuleProperties.INTERACTIVE_LANGUAGE_TAG.getRequired(session);
    }

    protected String getExchangeSubMethods(ClientSession session) {
        return CoreModuleProperties.INTERACTIVE_SUBMETHODS.getRequired(session);
    }

    protected String getCurrentPasswordCandidate() {
        if ((passwords != null) && passwords.hasNext()) {
            return passwords.next();
        } else {
            return null;
        }
    }

    protected boolean verifyTrialsCount(
            ClientSession session, String service, int cmd, int nbTrials, int maxAllowed) {
        if (log.isDebugEnabled()) {
            log.debug("verifyTrialsCount({})[{}] cmd={} - {} out of {}",
                    session, service, getAuthCommandName(cmd), nbTrials, maxAllowed);
        }

        return nbTrials <= maxAllowed;
    }

    /**
     * @param  name        The interaction name - may be empty
     * @param  instruction The instruction - may be empty
     * @param  lang        The language tag - may be empty
     * @param  prompt      The prompts - may be empty
     * @param  echo        Whether to echo the response for the prompt or not - same length as the prompts
     * @return             The response for each prompt - if {@code null} then the assumption is that some internal
     *                     error occurred and no response is sent. <B>Note:</B> according to
     *                     <A HREF="https://tools.ietf.org/html/rfc4256">RFC4256</A> the number of responses should be
     *                     <U>exactly</U> the same as the number of prompts. However, since it is the <U>server's</U>
     *                     responsibility to enforce this we do not validate the response (other than logging it as a
     *                     warning...)
     */
    protected String[] getUserResponses(
            String name, String instruction, String lang, String[] prompt, boolean[] echo) {
        ClientSession session = getClientSession();
        int num = GenericUtils.length(prompt);
        boolean debugEnabled = log.isDebugEnabled();
        /*
         * According to RFC 4256 - section 3.4
         *
         * In the case that the server sends a `0' num-prompts field in the request message, the client MUST send a
         * response message with a `0' num-responses field to complete the exchange.
         */
        if (num == 0) {
            if (debugEnabled) {
                log.debug("getUserResponses({}) no prompts for interaction={}", session, name);
            }
            return GenericUtils.EMPTY_STRING_ARRAY;
        }

        if (PropertyResolverUtils.getBooleanProperty(
                session, UserInteraction.AUTO_DETECT_PASSWORD_PROMPT,
                UserInteraction.DEFAULT_AUTO_DETECT_PASSWORD_PROMPT)) {
            String candidate = getCurrentPasswordCandidate();
            if (useCurrentPassword(session, candidate, name, instruction, lang, prompt, echo)) {
                if (debugEnabled) {
                    log.debug("getUserResponses({}) use password candidate for interaction={}", session, name);
                }
                return new String[] { candidate };
            }
        }

        UserInteraction ui = session.getUserInteraction();
        try {
            if ((ui != null) && ui.isInteractionAllowed(session)) {
                return ui.interactive(session, name, instruction, lang, prompt, echo);
            }
        } catch (Error e) {
            warn("getUserResponses({}) failed ({}) to consult interaction: {}",
                    session, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        if (debugEnabled) {
            log.debug("getUserResponses({}) no user interaction for name={}", session, name);
        }

        return null;
    }

    /**
     * Checks if we have a candidate password and <U>exactly one</U> prompt is requested with no echo, and the prompt
     * matches a configurable pattern.
     *
     * @param  session     The {@link ClientSession} through which the request is received
     * @param  password    The current password candidate to use
     * @param  name        The service name
     * @param  instruction The request instruction
     * @param  lang        The reported language tag
     * @param  prompt      The requested prompts
     * @param  echo        The matching prompts echo flags
     * @return             Whether to use the password candidate as reply to the prompts
     * @see                UserInteraction#INTERACTIVE_PASSWORD_PROMPT INTERACTIVE_PASSWORD_PROMPT
     * @see                UserInteraction#CHECK_INTERACTIVE_PASSWORD_DELIM CHECK_INTERACTIVE_PASSWORD_DELIM
     */
    protected boolean useCurrentPassword(
            ClientSession session, String password, String name,
            String instruction, String lang, String[] prompt, boolean[] echo) {
        int num = GenericUtils.length(prompt);
        if ((num != 1) || (password == null) || echo[0]) {
            return false;
        }

        // check if prompt is something like "XXX password YYY:"
        String value = GenericUtils.trimToEmpty(prompt[0]);
        // Don't care about the case
        value = value.toLowerCase();

        String promptList = PropertyResolverUtils.getStringProperty(
                session, UserInteraction.INTERACTIVE_PASSWORD_PROMPT,
                UserInteraction.DEFAULT_INTERACTIVE_PASSWORD_PROMPT);
        int passPos = UserInteraction.findPromptComponentLastPosition(value, promptList);
        if (passPos < 0) { // no password keyword in prompt
            return false;
        }

        String delimList = PropertyResolverUtils.getStringProperty(
                session, UserInteraction.CHECK_INTERACTIVE_PASSWORD_DELIM,
                UserInteraction.DEFAULT_CHECK_INTERACTIVE_PASSWORD_DELIM);
        if (PropertyResolverUtils.isNoneValue(delimList)) {
            return true;
        }

        int sepPos = UserInteraction.findPromptComponentLastPosition(value, delimList);
        if (sepPos < passPos) {
            return false;
        }

        return true;
    }

    public static String getAuthCommandName(int cmd) {
        switch (cmd) {
            case SshConstants.SSH_MSG_USERAUTH_REQUEST:
                return "SSH_MSG_USERAUTH_REQUEST";
            case SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST:
                return "SSH_MSG_USERAUTH_INFO_REQUEST";
            default:
                return SshConstants.getCommandMessageName(cmd);
        }
    }
}
