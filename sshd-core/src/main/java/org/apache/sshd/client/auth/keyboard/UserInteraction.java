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

import java.security.KeyPair;
import java.util.List;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Interface used by the ssh client to communicate with the end user.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://tools.ietf.org/html/rfc4256">RFC 4256</A>
 */
public interface UserInteraction {
    /**
     * Whether to auto-detect password challenge prompt
     *
     * @see #INTERACTIVE_PASSWORD_PROMPT
     * @see #CHECK_INTERACTIVE_PASSWORD_DELIM
     */
    String AUTO_DETECT_PASSWORD_PROMPT = "user-interaction-auto-detect-password-prompt";

    /** Default value for {@value #AUTO_DETECT_PASSWORD_PROMPT} */
    boolean DEFAULT_AUTO_DETECT_PASSWORD_PROMPT = true;

    /**
     * Comma separated list of values used to detect request for a password in interactive mode. <B>Note:</B> the
     * matched prompt is assumed to be <U>lowercase</U>.
     */
    String INTERACTIVE_PASSWORD_PROMPT = "user-interaction-password-prompt";

    /** Default value for {@value #INTERACTIVE_PASSWORD_PROMPT} */
    String DEFAULT_INTERACTIVE_PASSWORD_PROMPT = "password";

    /**
     * If password prompt detected then check it ends with <U>any</U> of the comma separated list of these values. Use
     * &quot;none&quot; to disable this extra check. <B>Note:</B> the matched prompt is assumed to be <U>lowercase</U>.
     */
    String CHECK_INTERACTIVE_PASSWORD_DELIM = "user-interaction-check-password-delimiter";

    /** Default value of {@value #CHECK_INTERACTIVE_PASSWORD_DELIM} */
    String DEFAULT_CHECK_INTERACTIVE_PASSWORD_DELIM = ":";

    /**
     * A useful &quot;placeholder&quot; that indicates that no interaction is expected. <B>Note:</B> throws
     * {@link IllegalStateException} is any of the interaction methods is called
     */
    UserInteraction NONE = new UserInteraction() {
        @Override
        public boolean isInteractionAllowed(ClientSession session) {
            return false;
        }

        @Override
        public String[] interactive(
                ClientSession session, String name, String instruction,
                String lang, String[] prompt, boolean[] echo) {
            throw new IllegalStateException("interactive(" + session + ")[" + name + "] unexpected call");
        }

        @Override
        public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
            throw new IllegalStateException("getUpdatedPassword(" + session + ")[" + prompt + "] unexpected call");
        }

        @Override
        public String toString() {
            return "NONE";
        }
    };

    /**
     * @param  session The {@link ClientSession}
     * @return         {@code true} if user interaction allowed for this session (default)
     */
    default boolean isInteractionAllowed(ClientSession session) {
        return true;
    }

    /**
     * Called if the server sent any extra information beyond the standard version line
     *
     * @param session The {@link ClientSession} through which this information was received
     * @param lines   The sent extra lines - <U>without</U> the server version
     * @see           <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>
     */
    default void serverVersionInfo(ClientSession session, List<String> lines) {
        // do nothing
    }

    /**
     * Displays the welcome banner to the user.
     *
     * @param session The {@link ClientSession} through which the banner was received
     * @param banner  The welcome banner
     * @param lang    The banner language code - may be empty
     */
    default void welcome(ClientSession session, String banner, String lang) {
        // do nothing
    }

    /**
     * Invoked when &quot;keyboard-interactive&quot; authentication mechanism is used in order to provide responses for
     * the server's challenges (a.k.a. prompts)
     *
     * @param  session     The {@link ClientSession} through which the request was received
     * @param  name        The interaction name (may be empty)
     * @param  instruction The instruction (may be empty)
     * @param  lang        The language for the data (may be empty)
     * @param  prompt      The prompts to be displayed (may be empty)
     * @param  echo        For each prompt whether to echo the user's response
     * @return             The replies - <B>Note:</B> the protocol states that the number of replies should be
     *                     <U>exactly</U> the same as the number of prompts, however we do not enforce it since it is
     *                     defined as the <U>server's</U> job to check and manage this violation.
     */
    String[] interactive(
            ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo);

    /**
     * Invoked when the server returns an {@code SSH_MSG_USERAUTH_PASSWD_CHANGEREQ} response indicating that the
     * password should be changed - e.g., expired or not strong enough (as per the server's policy).
     *
     * @param  session The {@link ClientSession} through which the request was received
     * @param  prompt  The server's prompt (may be empty)
     * @param  lang    The prompt's language (may be empty)
     * @return         The password to use - if {@code null}/empty then no updated password was provided - thus failing
     *                 the authentication via passwords (<B>Note:</B> authentication might still succeed via some other
     *                 means - be it other passwords, public keys, etc...)
     */
    String getUpdatedPassword(ClientSession session, String prompt, String lang);

    /**
     * Invoked during password authentication when no more pre-registered passwords are available
     *
     * @param  session   The {@link ClientSession} through which the request was received
     * @return           The password to use - {@code null} signals no more passwords available
     * @throws Exception if failed to handle the request - <B>Note:</B> may cause session termination
     */
    default String resolveAuthPasswordAttempt(ClientSession session) throws Exception {
        return null;
    }

    /**
     * Invoked during public key authentication when no more pre-registered keys are available
     *
     * @param  session   The {@link ClientSession} through which the request was received
     * @return           The {@link KeyPair} to use - {@code null} signals no more keys available
     * @throws Exception if failed to handle the request - <B>Note:</B> may cause session termination
     */
    default KeyPair resolveAuthPublicKeyIdentityAttempt(ClientSession session) throws Exception {
        return null;
    }

    /**
     * @param  prompt     The user interaction prompt
     * @param  tokensList A comma-separated list of tokens whose <U>last</U> index is prompt is sought.
     * @return            The position of any token in the prompt - negative if not found
     */
    static int findPromptComponentLastPosition(String prompt, String tokensList) {
        if (GenericUtils.isEmpty(prompt) || GenericUtils.isEmpty(tokensList)) {
            return -1;
        }

        String[] tokens = GenericUtils.split(tokensList, ',');
        for (String t : tokens) {
            int pos = prompt.lastIndexOf(t);
            if (pos >= 0) {
                return pos;
            }
        }

        return -1;
    }
}
