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

package org.apache.sshd.server.auth.password;

/**
 * A special exception that can be thrown by the {@link PasswordAuthenticator} to indicate that the password requires
 * changing or is not string enough
 *
 * @see    <A HREF="https://tools.ietf.org/html/rfc4252#section-8">RFC-4252 section 8 -
 *         SSH_MSG_USERAUTH_PASSWD_CHANGEREQ</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PasswordChangeRequiredException extends RuntimeException {
    private static final long serialVersionUID = -8522928326608137895L;
    private final String prompt;
    private final String lang;

    public PasswordChangeRequiredException(String message, String prompt, String lang) {
        this(message, prompt, lang, null);
    }

    public PasswordChangeRequiredException(Throwable cause, String prompt, String lang) {
        this(cause.getMessage(), prompt, lang, cause);
    }

    public PasswordChangeRequiredException(String message, String prompt, String lang, Throwable cause) {
        super(message, cause);
        this.prompt = prompt;
        this.lang = lang;
    }

    /**
     * @return The prompt to show to the user - may be {@code null}/empty
     */
    public final String getPrompt() {
        return prompt;
    }

    /**
     * @return The language code for the prompt - may be {@code null}/empty
     */
    public final String getLanguage() {
        return lang;
    }
}
