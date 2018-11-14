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

package org.apache.sshd.common.session;

import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.ConnectionEndpointsIndicator;

/**
 * A &quot;succinct&quot; summary of the most important attributes of an SSH session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SessionContext
        extends ConnectionEndpointsIndicator,
                UsernameHolder,
                PropertyResolver,
                AttributeStore {
    /**
     * Default prefix expected for the client / server identification string
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>
     */
    String DEFAULT_SSH_VERSION_PREFIX = "SSH-2.0-";

    /**
     * Backward compatible special prefix
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-5">RFC 4253 - section 5</A>
     */
    String FALLBACK_SSH_VERSION_PREFIX = "SSH-1.99-";

    /**
     * Maximum number of characters for any single line sent as part
     * of the initial handshake - according to
     * <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>:</BR>
     *
     * <P><CODE>
     *      The maximum length of the string is 255 characters,
     *      including the Carriage Return and Line Feed.
     * </CODE></P>
     */
    int MAX_VERSION_LINE_LENGTH = 256;

    /**
     * @return A <U>clone</U> of the established session identifier - {@code null} if
     * not yet established
     */
    byte[] getSessionId();

    /**
     * Retrieve the client version for this session.
     *
     * @return the client version - may be {@code null}/empty if versions not yet exchanged
     */
    String getClientVersion();

    /**
     * Retrieve the server version for this session.
     *
     * @return the server version - may be {@code null}/empty if versions not yet exchanged
     */
    String getServerVersion();

    /**
     * @return {@code true} if session has successfully completed the authentication phase
     */
    boolean isAuthenticated();

    /**
     * @param version The reported client/server version
     * @return {@code true} if version not empty and starts with either
     * {@value #DEFAULT_SSH_VERSION_PREFIX} or {@value #FALLBACK_SSH_VERSION_PREFIX}
     */
    static boolean isValidVersionPrefix(String version) {
        return GenericUtils.isNotEmpty(version)
            && (version.startsWith(DEFAULT_SSH_VERSION_PREFIX) || version.startsWith(FALLBACK_SSH_VERSION_PREFIX));
    }
}
