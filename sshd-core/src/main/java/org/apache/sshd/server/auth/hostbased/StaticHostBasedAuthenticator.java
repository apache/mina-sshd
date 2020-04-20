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

package org.apache.sshd.server.auth.hostbased;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class StaticHostBasedAuthenticator extends AbstractLoggingBean implements HostBasedAuthenticator {
    private final boolean acceptance;

    public StaticHostBasedAuthenticator(boolean acceptance) {
        this.acceptance = acceptance;
    }

    public final boolean isAccepted() {
        return acceptance;
    }

    @Override
    public final boolean authenticate(
            ServerSession session, String username, PublicKey clientHostKey,
            String clientHostName, String clientUsername, List<X509Certificate> certificates) {
        boolean accepted = isAccepted();
        if (accepted) {
            handleAcceptance(session, username, clientHostKey, clientHostName, clientUsername, certificates);
        } else {
            handleRejection(session, username, clientHostKey, clientHostName, clientUsername, certificates);
        }

        return accepted;
    }

    protected void handleAcceptance(
            ServerSession session, String username, PublicKey clientHostKey,
            String clientHostName, String clientUsername, List<X509Certificate> certificates) {
        // accepting without really checking is dangerous, thus the warning
        log.warn("authenticate({}[{}]: accepted without checking {}@{} key={} fingerprint={}",
                username, session, clientUsername, clientHostName, KeyUtils.getKeyType(clientHostKey),
                KeyUtils.getFingerPrint(clientHostKey));

    }

    protected void handleRejection(
            ServerSession session, String username, PublicKey clientHostKey,
            String clientHostName, String clientUsername, List<X509Certificate> certificates) {
        if (log.isDebugEnabled()) {
            log.debug("authenticate({}[{}]: rejected {}@{} key={} fingerprint={}",
                    username, session, clientUsername, clientHostName, KeyUtils.getKeyType(clientHostKey),
                    KeyUtils.getFingerPrint(clientHostKey));
        }
    }
}
