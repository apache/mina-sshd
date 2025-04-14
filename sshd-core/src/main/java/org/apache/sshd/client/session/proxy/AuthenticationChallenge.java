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
package org.apache.sshd.client.session.proxy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A simple representation of an authentication challenge as sent in a "WWW-Authenticate" or "Proxy-Authenticate"
 * header. Such challenges start with a mechanism name, followed either by one single token, or by a list of key=value
 * pairs.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7235#section-2.1">RFC 7235, sec. 2.1</a>
 */
public class AuthenticationChallenge {

    private final String mechanism;

    private String token;

    private Map<String, String> arguments;

    /**
     * Create a new {@link AuthenticationChallenge} with the given mechanism.
     *
     * @param mechanism for the challenge
     */
    public AuthenticationChallenge(String mechanism) {
        this.mechanism = mechanism;
    }

    /**
     * Retrieves the authentication mechanism specified by this challenge, for instance "Basic".
     *
     * @return the mechanism name
     */
    public String getMechanism() {
        return mechanism;
    }

    /**
     * Retrieves the token of the challenge, if any.
     *
     * @return the token, or {@code null} if there is none.
     */
    public String getToken() {
        return token;
    }

    /**
     * Retrieves the arguments of the challenge.
     *
     * @return a possibly empty map of the key=value arguments of the challenge
     */
    public Map<String, String> getArguments() {
        return arguments == null ? Collections.emptyMap() : arguments;
    }

    void addArgument(String key, String value) {
        if (arguments == null) {
            arguments = new LinkedHashMap<>();
        }
        arguments.put(key, value);
    }

    void setToken(String token) {
        this.token = token;
    }

    @Override
    public String toString() {
        return "AuthenticationChallenge[" + mechanism + ',' + token + ',' //$NON-NLS-1$
               + (arguments == null ? "<none>" : arguments.toString()) + ']'; //$NON-NLS-1$
    }
}
