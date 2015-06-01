/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server;

import java.security.PublicKey;

import org.apache.sshd.common.util.AbstractLoggingBean;
import org.apache.sshd.common.util.KeyUtils;
import org.apache.sshd.server.session.ServerSession;

/**
 * The <code>PublickeyAuthenticator</code> is used on the server side
 * to authenticate user public keys.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublickeyAuthenticator {

    /**
     * Check the validity of a public key.
     * @param username the username
     * @param key the key
     * @param session the server session
     * @return a boolean indicating if authentication succeeded or not
     */
    boolean authenticate(String username, PublicKey key, ServerSession session);

    /**
     * Returns the same constant result {@code true/false} regardless
     */
    public static abstract class StaticPublickeyAuthenticator extends AbstractLoggingBean implements PublickeyAuthenticator {
        private final boolean   acceptance;

        protected StaticPublickeyAuthenticator(boolean acceptance) {
            this.acceptance = acceptance;
        }

        public final boolean isAccepted() {
            return acceptance;
        }

        @Override
        public final boolean authenticate(String username, PublicKey key, ServerSession session) {
            boolean accepted = isAccepted();
            if (log.isDebugEnabled()) {
                log.debug("authenticate({}[{}][{}][{}]: {}",
                          username, session, key.getAlgorithm(), KeyUtils.getFingerPrint(key), Boolean.valueOf(accepted));
            }

            return accepted;
        }
    }

    /**
     * Accepts all authentication attempts
     */
    public static final class AcceptAllPublickeyAuthenticator extends StaticPublickeyAuthenticator {
        public static final AcceptAllPublickeyAuthenticator INSTANCE = new AcceptAllPublickeyAuthenticator();

        private AcceptAllPublickeyAuthenticator() {
            super(true);
        }
    }

    /**
     * Rejects all authentication attempts
     */
    public static final class RejectAllPublickeyAuthenticator extends StaticPublickeyAuthenticator {
        public static final RejectAllPublickeyAuthenticator INSTANCE = new RejectAllPublickeyAuthenticator();

        private RejectAllPublickeyAuthenticator() {
            super(false);
        }
    }
}
