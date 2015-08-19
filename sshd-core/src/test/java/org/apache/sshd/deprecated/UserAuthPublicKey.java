/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
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

import org.apache.sshd.client.auth.UserAuthPublicKeyFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey extends AbstractUserAuth {
    private final KeyPair key;

    public UserAuthPublicKey(ClientSession session, String service, KeyPair key) {
        super(session, service);
        this.key = key;
    }

    @Override
    public Result next(Buffer buffer) throws IOException {
        if (buffer == null) {
            try {
                log.debug("Send SSH_MSG_USERAUTH_REQUEST for publickey");
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                buffer.putString(session.getUsername());
                buffer.putString(service);
                buffer.putString(UserAuthPublicKeyFactory.NAME);
                buffer.putBoolean(true);
                String alg = KeyUtils.getKeyType(key);
                buffer.putString(alg);
                buffer.putPublicKey(key.getPublic());

                FactoryManager manager = session.getFactoryManager();
                Signature verif =
                        ValidateUtils.checkNotNull(NamedFactory.Utils.create(manager.getSignatureFactories(), alg),
                                "No signature factory located for algorithm=%s",
                                alg);
                verif.initSigner(key.getPrivate());

                Buffer bs = new ByteArrayBuffer();
                bs.putBytes(session.getKex().getH());
                bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                bs.putString(session.getUsername());
                bs.putString(service);
                bs.putString(UserAuthPublicKeyFactory.NAME);
                bs.putBoolean(true);
                bs.putString(alg);
                bs.putPublicKey(key.getPublic());
                verif.update(bs.array(), bs.rpos(), bs.available());

                bs = new ByteArrayBuffer();
                bs.putString(alg);
                bs.putBytes(verif.sign());
                buffer.putBytes(bs.array(), bs.rpos(), bs.available());

                session.writePacket(buffer);
                return Result.Continued;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw (IOException) new IOException("Error performing public key authentication").initCause(e);
            }
        } else {
            int cmd = buffer.getUByte();
            if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                log.debug("Received SSH_MSG_USERAUTH_SUCCESS");
                return Result.Success;
            }
            if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                log.debug("Received SSH_MSG_USERAUTH_FAILURE");
                return Result.Failure;
            } else {
                log.debug("Received unknown packet {}", Integer.valueOf(cmd));
                // TODO: check packets
                return Result.Continued;
            }
        }
    }
}
