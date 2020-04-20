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

import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * Returns the same constant result {@code true/false} regardless
 */
public class StaticPasswordAuthenticator extends AbstractLoggingBean implements PasswordAuthenticator {
    private final boolean acceptance;

    public StaticPasswordAuthenticator(boolean acceptance) {
        this.acceptance = acceptance;
    }

    public final boolean isAccepted() {
        return acceptance;
    }

    @Override
    public final boolean authenticate(String username, String password, ServerSession session) {
        boolean accepted = isAccepted();
        if (accepted) {
            handleAcceptance(username, password, session);
        } else {
            handleRejection(username, password, session);
        }

        return accepted;
    }

    protected void handleAcceptance(String username, String password, ServerSession session) {
        // accepting without really checking is dangerous, thus the warning
        log.warn("authenticate({}[{}]: accepted without checking", username, session);
    }

    protected void handleRejection(String username, String password, ServerSession session) {
        if (log.isDebugEnabled()) {
            log.debug("authenticate({}[{}]: rejected", username, session);
        }
    }
}
