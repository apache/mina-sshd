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
package org.apache.sshd.server.auth;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.UserAuth;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class UserAuthPublicKey implements UserAuth {

    public static class Factory implements NamedFactory<UserAuth> {
        public String getName() {
            return "publickey";
        }
        public UserAuth create() {
            return new UserAuthPublicKey();
        }
    }

    public Object auth(ServerSession session, String username, Buffer buffer) throws Exception {
        boolean hasSig = buffer.getBoolean();
        String alg = buffer.getString();

        int oldLim = buffer.wpos();
        int oldPos = buffer.rpos();
        int len = buffer.getInt();
        buffer.wpos(buffer.rpos() + len);
        PublicKey key = buffer.getPublicKey();
        String keyAlg = (key instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS;

        Signature verif = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), keyAlg);
        verif.init(key, null);
        buffer.wpos(oldLim);

        byte[] sig = hasSig ? buffer.getBytes() : null;

        PublickeyAuthenticator authenticator = session.getServerFactoryManager().getPublickeyAuthenticator();
        if (authenticator == null) {
            throw new Exception("No PublickeyAuthenticator configured");
        }

        if (!hasSig) {
            if (authenticator.hasKey(username, key, session)) {
                Buffer buf = session.createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_PK_OK);
                buf.putString(alg);
                buf.putRawBytes(buffer.array(), oldPos, 4 + len);
                session.writePacket(buf);
                return null;
            } else {
                throw new Exception("Unsupported key for user");
            }
        } else {
            if (!authenticator.hasKey(username, key, session)) {
                throw new Exception("Unsupported key for user");
            }
            Buffer buf = new Buffer();
            buf.putString(session.getKex().getH());
            buf.putCommand(SshConstants.Message.SSH_MSG_USERAUTH_REQUEST);
            buf.putString(username);
            buf.putString("ssh-connection");
            buf.putString("publickey");
            buf.putByte((byte) 1);
            buf.putString(keyAlg);
            buffer.rpos(oldPos);
            buffer.wpos(oldPos + 4 + len);
            buf.putBuffer(buffer);
            verif.update(buf.array(), buf.rpos(), buf.available());
            if (verif.verify(sig)) {
                return username;
            } else {
                throw new Exception("Key verification failed");
            }
        }
    }
}
