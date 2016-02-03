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
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A ServerKeyVerifier that accepts one server key (specified in the constructor)
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RequiredServerKeyVerifier extends AbstractLoggingBean implements ServerKeyVerifier {
    private final PublicKey requiredKey;

    public RequiredServerKeyVerifier(PublicKey requiredKey) {
        this.requiredKey = requiredKey;
    }

    public final PublicKey getRequiredKey() {
        return requiredKey;
    }

    @Override
    public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        if (requiredKey.equals(serverKey)) {
            if (log.isDebugEnabled()) {
                log.debug("Server at {} presented expected key: {}", remoteAddress, BufferUtils.toHex(serverKey.getEncoded()));
            }
            return true;
        } else {
            log.error("Server at {} presented wrong key: {}", remoteAddress, BufferUtils.toHex(serverKey.getEncoded()));
            return false;
        }
    }
}
