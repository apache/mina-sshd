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

package org.apache.sshd.client.keyverifier;

import java.net.SocketAddress;
import java.security.PublicKey;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Returns the same constant answer {@code true/false} regardless
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class StaticServerKeyVerifier extends AbstractLoggingBean implements ServerKeyVerifier {
    private final boolean acceptance;

    protected StaticServerKeyVerifier(boolean acceptance) {
        this.acceptance = acceptance;
    }

    public final boolean isAccepted() {
        return acceptance;
    }

    @Override
    public final boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        boolean accepted = isAccepted();
        if (accepted) {
            handleAcceptance(sshClientSession, remoteAddress, serverKey);
        } else {
            handleRejection(sshClientSession, remoteAddress, serverKey);
        }

        return accepted;
    }

    protected void handleAcceptance(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        // accepting without really checking is dangerous, thus the warning
        log.warn("Server at {} presented unverified {} key: {}",
                remoteAddress, (serverKey == null) ? null : serverKey.getAlgorithm(), KeyUtils.getFingerPrint(serverKey));
    }

    protected void handleRejection(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        if (log.isDebugEnabled()) {
            log.debug("Reject server {} unverified {} key: {}",
                    remoteAddress, (serverKey == null) ? null : serverKey.getAlgorithm(), KeyUtils.getFingerPrint(serverKey));
        }
    }
}
