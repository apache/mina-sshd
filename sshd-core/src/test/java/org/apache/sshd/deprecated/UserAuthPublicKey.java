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

package org.apache.sshd.deprecated;

import java.io.IOException;
import java.security.KeyPair;

import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
// CHECKSTYLE:OFF
public class UserAuthPublicKey extends AbstractUserAuth {
    private final KeyPair key;

    public UserAuthPublicKey(ClientSession session, String service, KeyPair key) {
        super(session, service);
        this.key = key;
    }

    @Override
    public Result next(Buffer buffer) throws IOException {
        ClientSession session = getClientSession();
        String service = getService();
        boolean debugEnabled = log.isDebugEnabled();
        if (buffer == null) {
            try {
                if (debugEnabled) {
                    log.debug("Send SSH_MSG_USERAUTH_REQUEST for publickey");
                }
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                buffer.putString(session.getUsername());
                buffer.putString(service);
                buffer.putString(UserAuthPublicKeyFactory.NAME);
                buffer.putBoolean(true);
                String alg = KeyUtils.getKeyType(key);
                buffer.putString(alg);
                buffer.putPublicKey(key.getPublic());

                Signature verif =
                    ValidateUtils.checkNotNull(NamedFactory.create(session.getSignatureFactories(), alg),
                        "No signature factory located for algorithm=%s",
                        alg);
                verif.initSigner(session, key.getPrivate());

                KeyExchange kexValue = session.getKex();
                byte[] hValue = kexValue.getH();
                Buffer bs = new ByteArrayBuffer();
                bs.putBytes(hValue);
                bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                bs.putString(session.getUsername());
                bs.putString(service);
                bs.putString(UserAuthPublicKeyFactory.NAME);
                bs.putBoolean(true);
                bs.putString(alg);
                bs.putPublicKey(key.getPublic());
                verif.update(session, bs.array(), bs.rpos(), bs.available());

                byte[] signature = verif.sign(session);
                bs = new ByteArrayBuffer(alg.length() + signature.length + Long.SIZE, false);
                bs.putString(alg);
                bs.putBytes(signature);
                buffer.putBytes(bs.array(), bs.rpos(), bs.available());

                session.writePacket(buffer);
                return Result.Continued;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("Error performing public key authentication", e);
            }
        } else {
            int cmd = buffer.getUByte();
            if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                if (debugEnabled) {
                    log.debug("Received SSH_MSG_USERAUTH_SUCCESS");
                }
                return Result.Success;
            }
            if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                String methods = buffer.getString();
                boolean partial = buffer.getBoolean();
                if (debugEnabled) {
                    log.debug("Received SSH_MSG_USERAUTH_FAILURE - partial={}, methods={}", partial, methods);
                }
                return Result.Failure;
            } else {
                if (debugEnabled) {
                    log.debug("Received unknown packet {}", cmd);
                }
                // TODO: check packets
                return Result.Continued;
            }
        }
    }
}
// CHECKSTYLE:ON
