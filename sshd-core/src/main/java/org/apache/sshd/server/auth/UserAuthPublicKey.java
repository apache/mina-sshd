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

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.UserAuth;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey extends AbstractUserAuth {

    public static class Factory implements NamedFactory<UserAuth> {
        public String getName() {
            return "publickey";
        }
        public UserAuth create() {
            return new UserAuthPublicKey();
        }
    }

    public Boolean doAuth(Buffer buffer, boolean init) throws Exception {
        if (!init) {
            throw new IllegalStateException();
        }
        boolean hasSig = buffer.getBoolean();
        String alg = buffer.getString();

        int oldLim = buffer.wpos();
        int oldPos = buffer.rpos();
        int len = buffer.getInt();
        buffer.wpos(buffer.rpos() + len);
        PublicKey key = buffer.getRawPublicKey();
        Signature verif = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), alg);
        if (verif == null) {
            throw new Exception("No Signature available for: " + alg);
        }
        verif.init(key, null);
        buffer.wpos(oldLim);

        byte[] sig = hasSig ? buffer.getBytes() : null;

        PublickeyAuthenticator authenticator = session.getFactoryManager().getPublickeyAuthenticator();
        if (authenticator == null) {
            throw new Exception("No PublickeyAuthenticator configured");
        }

        if (!authenticator.authenticate(username, key, session)) {
            return false;
        }
        if (!hasSig) {
            Buffer buf = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_PK_OK);
            buf.putString(alg);
            buf.putRawBytes(buffer.array(), oldPos, 4 + len);
            session.writePacket(buf);
            return null;
        } else {
            Buffer buf = new Buffer();
            buf.putString(session.getKex().getH());
            buf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            buf.putString(username);
            buf.putString(service);
            buf.putString("publickey");
            buf.putByte((byte) 1);
            buf.putString(alg);
            buffer.rpos(oldPos);
            buffer.wpos(oldPos + 4 + len);
            buf.putBuffer(buffer);
            verif.update(buf.array(), buf.rpos(), buf.available());
            if (!verif.verify(sig)) {
                throw new Exception("Key verification failed");
            }
            return true;
        }
    }
}
