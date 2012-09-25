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
package org.apache.sshd.client.auth;

import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey implements UserAuth {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final ClientSessionImpl session;
    private final String username;
    private final KeyPair key;

    public UserAuthPublicKey(ClientSessionImpl session, String username, KeyPair key) {
        this.session = session;
        this.username = username;
        this.key = key;
    }

    public String getUsername() {
        return username;
    }

    public Result next(Buffer buffer) throws IOException {
        if (buffer == null) {
            try {
                log.info("Send SSH_MSG_USERAUTH_REQUEST for publickey");
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_REQUEST, 0);
                int pos1 = buffer.wpos() - 1;
                buffer.putString(username);
                buffer.putString("ssh-connection");
                buffer.putString("publickey");
                buffer.putByte((byte) 1);
                buffer.putString((key.getPublic() instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
                int pos2 = buffer.wpos();
                buffer.putPublicKey(key.getPublic());

                Signature verif = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), (key.getPublic() instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
                verif.init(key.getPublic(), key.getPrivate());

                Buffer bs = new Buffer();
                bs.putString(session.getKex().getH());
                bs.putCommand(SshConstants.Message.SSH_MSG_USERAUTH_REQUEST);
                bs.putString(username);
                bs.putString("ssh-connection");
                bs.putString("publickey");
                bs.putByte((byte) 1);
                bs.putString((key.getPublic() instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
                bs.putPublicKey(key.getPublic());
                verif.update(bs.array(), bs.rpos(), bs.available());

                bs = new Buffer();
                bs.putString((key.getPublic() instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
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
            SshConstants.Message cmd = buffer.getCommand();
            log.info("Received {}", cmd);
            if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_SUCCESS) {
                return Result.Success;
            } if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_FAILURE) {
                return Result.Failure;
            } else {
                // TODO: check packets
                return Result.Continued;
            }
        }
    }

}
