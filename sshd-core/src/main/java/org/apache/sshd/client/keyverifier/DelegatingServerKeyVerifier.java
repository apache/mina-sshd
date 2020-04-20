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
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A {@link ServerKeyVerifier} that delegates verification to the instance found in the {@link ClientSession} metadata
 * The verifier can be specified at the {@code SshClient} level, which may have connections to multiple hosts. This
 * technique lets each connection have its own verifier instance.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DelegatingServerKeyVerifier extends AbstractLoggingBean implements ServerKeyVerifier {
    public DelegatingServerKeyVerifier() {
        super();
    }

    @Override
    public boolean verifyServerKey(
            ClientSession session, SocketAddress remoteAddress, PublicKey serverKey) {
        Map<Object, Object> metadataMap = session.getMetadataMap();
        Object verifier = metadataMap.get(ServerKeyVerifier.class);
        if (verifier == null) {
            if (log.isTraceEnabled()) {
                log.trace("verifyServerKey({}) No verifier found in ClientSession metadata; accepting server key",
                        remoteAddress);
            }
            return true;
        }
        // We throw if it's not a ServerKeyVerifier...
        return ((ServerKeyVerifier) verifier).verifyServerKey(session, remoteAddress, serverKey);
    }
}
