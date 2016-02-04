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

import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.ClientAuthenticationManager;
import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Manages a &quot;keyboard-interactive&quot; exchange according to
 * <A HREF="https://www.ietf.org/rfc/rfc4256.txt">RFC4256</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthKeyboardInteractive extends AbstractUserAuth {
    public static final String NAME = UserAuthKeyboardInteractiveFactory.NAME;

    public static final String INTERACTIVE_LANGUAGE_TAG = "kb-client-interactive-language-tag";

    /*
     * As per RFC-4256:
     *
     *      The language tag is deprecated and SHOULD be the empty string.  It
     *      may be removed in a future revision of this specification.  Instead,
     *      the server SHOULD select the language to be used based on the tags
     *      communicated during key exchange
     */
    public static final String DEFAULT_INTERACTIVE_LANGUAGE_TAG = "";

    public static final String INTERACTIVE_SUBMETHODS = "kb-client-interactive-sub-methods";

    /*
     * As per RFC-4256:
     *
     *      The submethods field is included so the user can give a hint of which
     *      actual methods he wants to use.  It is a comma-separated list of
     *      authentication submethods (software or hardware) that the user
     *      prefers.  If the client has knowledge of the submethods preferred by
     *      the user, presumably through a configuration setting, it MAY use the
     *      submethods field to pass this information to the server.  Otherwise,
     *      it MUST send the empty string.
     *
     *      The actual names of the submethods is something the user and the
     *      server need to agree upon.
     *
     *      Server interpretation of the submethods field is implementation-
     *      dependent.
     */
    public static final String DEFAULT_INTERACTIVE_SUBMETHODS = "";

    private final AtomicBoolean requestPending = new AtomicBoolean(false);
    private final AtomicInteger trialsCount = new AtomicInteger(0);
    private Iterator<String> passwords;
    private int maxTrials;

    public UserAuthKeyboardInteractive() {
        super(NAME);
    }

    @Override
    public void init(ClientSession session, String service) throws Exception {
        super.init(session, service);
        passwords = PasswordIdentityProvider.Utils.iteratorOf(session);
        maxTrials = PropertyResolverUtils.getIntProperty(session, ClientAuthenticationManager.PASSWORD_PROMPTS, ClientAuthenticationManager.DEFAULT_PASSWORD_PROMPTS);
        ValidateUtils.checkTrue(maxTrials > 0, "Non-positive max. trials: %d", maxTrials);
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        String name = getName();
        if (requestPending.get()) {
            if (log.isDebugEnabled()) {
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
        if (log.isDebugEnabled()) {
            log.debug("sendAuthDataRequest({})[{}] send SSH_MSG_USERAUTH_REQUEST for {}: lang={}, methods={}",
                      session, service, name, lang, subMethods);
        }

        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                            username.length() + service.length() + name.length()
                          + GenericUtils.length(lang) + GenericUtils.length(subMethods)
                          + Long.SIZE /* a bit extra for the lengths */);
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
            throw new IllegalStateException("processAuthDataRequest(" + session + ")[" + service + "]"
                            + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
        }

        requestPending.set(false);

        if (!verifyTrialsCount(session, service, cmd, trialsCount.incrementAndGet(), maxTrials)) {
            return false;
        }

        String name = buffer.getString();
        String instruction = buffer.getString();
        String lang = buffer.getString();
        int num = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("processAuthDataRequest({})[{}] SSH_MSG_USERAUTH_INFO_REQUEST name={}, instruction={}, language={}, num-prompts={}",
                      session, service, name, instruction, lang, num);
        }

        String[] prompt = new String[num];
        boolean[] echo = new boolean[num];
        for (int i = 0; i < num; i++) {
            // according to RFC4256: "The prompt field(s) MUST NOT be empty strings."
            prompt[i] = buffer.getString();
            echo[i] = buffer.getBoolean();
        }

        if (log.isTraceEnabled()) {
            log.trace("processAuthDataRequest({})[{}] Prompt: {}", session, service, Arrays.toString(prompt));
            log.trace("processAuthDataRequest({})[{}] Echo: {}", session, service, Arrays.toString(echo));
        }

        String[] rep = getUserResponses(name, instruction, lang, prompt, echo);
        if (rep == null) {
            if (log.isDebugEnabled()) {
                log.debug("processAuthDataRequest({})[{}] no responses for {}", session, service, name);
            }
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
            log.warn("processAuthDataRequest({})[{}] Mismatched prompts ({}) vs. responses count ({})",
                     session, service, num, rep.length);
        }

        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE, rep.length * Long.SIZE + Byte.SIZE);
        buffer.putInt(rep.length);
        for (int index = 0; index < rep.length; index++) {
            String r = rep[index];
            if (log.isTraceEnabled()) {
                log.trace("processAuthDataRequest({})[{}] response #{}: {}", session, service, index + 1, r);
            }
            buffer.putString(r);
        }

        session.writePacket(buffer);
        return true;
    }

    protected String getExchangeLanguageTag(ClientSession session) {
        return PropertyResolverUtils.getStringProperty(session, INTERACTIVE_LANGUAGE_TAG, DEFAULT_INTERACTIVE_LANGUAGE_TAG);
    }

    protected String getExchangeSubMethods(ClientSession session) {
        return PropertyResolverUtils.getStringProperty(session, INTERACTIVE_SUBMETHODS, DEFAULT_INTERACTIVE_SUBMETHODS);
    }

    protected String getCurrentPasswordCandidate() {
        if ((passwords != null) && passwords.hasNext()) {
            return passwords.next();
        } else {
            return null;
        }
    }

    protected boolean verifyTrialsCount(ClientSession session, String service, int cmd, int nbTrials, int maxAllowed) {
        if (log.isDebugEnabled()) {
            log.debug("verifyTrialsCount({})[{}] cmd={} - {} out of {}",
                      session, service, getAuthCommandName(cmd), nbTrials, maxAllowed);
        }

        return nbTrials <= maxAllowed;
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
        ClientSession session = getClientSession();
        int num = GenericUtils.length(prompt);
        if (num == 0) {
            if (log.isDebugEnabled()) {
                log.debug("getUserResponses({}) no prompts for interaction={}", session, name);
            }
            return GenericUtils.EMPTY_STRING_ARRAY;
        }

        String candidate = getCurrentPasswordCandidate();
        if (useCurrentPassword(candidate, name, instruction, lang, prompt, echo)) {
            if (log.isDebugEnabled()) {
                log.debug("getUserResponses({}) use password candidate for interaction={}", session, name);
            }
            return new String[]{candidate};
        }

        UserInteraction ui = session.getUserInteraction();
        try {
            if ((ui != null) && ui.isInteractionAllowed(session)) {
                return ui.interactive(session, name, instruction, lang, prompt, echo);
            }
        } catch (Error e) {
            log.warn("getUserResponses({}) failed ({}) to consult interaction: {}",
                     session, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("getUserResponses(" + session + ") interaction consultation failure details", e);
            }

            throw new RuntimeSshException(e);
        }

        if (log.isDebugEnabled()) {
            log.debug("getUserResponses({}) no user interaction for name={}", session, name);
        }

        return null;
    }

    protected boolean useCurrentPassword(String password, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
        int num = GenericUtils.length(prompt);
        if ((num != 1) || (password == null) || echo[0]) {
            return false;
        }

        // check that prompt is something like "XXX password YYY:"
        String value = GenericUtils.trimToEmpty(prompt[0]).toLowerCase();
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

    public static String getAuthCommandName(int cmd) {
        switch(cmd) {
            case SshConstants.SSH_MSG_USERAUTH_REQUEST:
                return "SSH_MSG_USERAUTH_REQUEST";
            case SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST:
                return "SSH_MSG_USERAUTH_INFO_REQUEST";
            default:
                return SshConstants.getCommandMessageName(cmd);
        }
    }
}
