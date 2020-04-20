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
package org.apache.sshd.server.auth.pubkey;

import java.security.PublicKey;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * Returns the same constant result {@code true/false} regardless
 */
public abstract class StaticPublickeyAuthenticator extends AbstractLoggingBean implements PublickeyAuthenticator {
    private final boolean acceptance;

    protected StaticPublickeyAuthenticator(boolean acceptance) {
        this.acceptance = acceptance;
    }

    public final boolean isAccepted() {
        return acceptance;
    }

    @Override
    public final boolean authenticate(String username, PublicKey key, ServerSession session) {
        boolean accepted = isAccepted();
        if (accepted) {
            handleAcceptance(username, key, session);
        }

        return accepted;
    }

    protected void handleAcceptance(String username, PublicKey key, ServerSession session) {
        // accepting without really checking is dangerous, thus the warning
        log.warn("authenticate({}[{}][{}][{}]: accepted without checking",
                username, session, (key == null) /* don't care about the key */ ? "null" : key.getAlgorithm(),
                KeyUtils.getFingerPrint(key));
    }

    protected void handleRejection(String username, PublicKey key, ServerSession session) {
        if (log.isDebugEnabled()) {
            log.debug("authenticate({}[{}][{}][{}]: rejected",
                    username, session, (key == null) /* don't care about the key */ ? "null" : key.getAlgorithm(),
                    KeyUtils.getFingerPrint(key));
        }
    }
}
