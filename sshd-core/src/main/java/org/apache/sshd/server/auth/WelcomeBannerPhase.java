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

package org.apache.sshd.server.auth;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Used to indicate at which authentication phase to send the welcome banner (if any configured)
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://tools.ietf.org/html/rfc4252#section-5.4">RFC-4252 section 5.4</a>
 */
public enum WelcomeBannerPhase {
    /** Immediately after receiving &quot;ssh-userauth&quot; request */
    IMMEDIATE,
    /** On first {@code SSH_MSG_USERAUTH_REQUEST} */
    FIRST_REQUEST,
    /** On first {@code SSH_MSG_USERAUTH_XXX} extension command */
    FIRST_AUTHCMD,
    /** On first {@code SSH_MSG_USERAUTH_FAILURE} */
    FIRST_FAILURE,
    /** After user successfully authenticates */
    POST_SUCCESS,
    /**
     * Do not send a welcome banner even if one is configured. <B>Note:</B> this option is useful when a global welcome
     * banner has been configured but we want to disable it for a specific session.
     */
    NEVER;

    public static final Set<WelcomeBannerPhase> VALUES = Collections.unmodifiableSet(EnumSet.allOf(WelcomeBannerPhase.class));
}
