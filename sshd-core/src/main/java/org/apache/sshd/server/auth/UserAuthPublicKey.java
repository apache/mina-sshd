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
package org.apache.sshd.server.auth;

import java.security.PublicKey;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey extends AbstractUserAuth {
    public static final String NAME = UserAuthPublicKeyFactory.NAME;

    public UserAuthPublicKey() {
        super(NAME);
    }

    @Override
    public Boolean doAuth(Buffer buffer, boolean init) throws Exception {
        ValidateUtils.checkTrue(init, "Instance not initialized");

        boolean hasSig = buffer.getBoolean();
        String alg = buffer.getString();
        int oldLim = buffer.wpos();
        int oldPos = buffer.rpos();
        int len = buffer.getInt();
        buffer.wpos(buffer.rpos() + len);

        ServerSession session = getServerSession();
        PublicKey key = buffer.getRawPublicKey();
        if (log.isDebugEnabled()) {
            log.debug("doAuth({}) verify key type={}, fingerprint={}",
                      session, alg, KeyUtils.getFingerPrint(key));
        }

        Signature verifier = ValidateUtils.checkNotNull(
                NamedFactory.Utils.create(session.getSignatureFactories(), alg),
                "No verifier located for algorithm=%s",
                alg);
        verifier.initVerifier(key);
        buffer.wpos(oldLim);

        byte[] sig = hasSig ? buffer.getBytes() : null;
        PublickeyAuthenticator authenticator = session.getPublickeyAuthenticator();
        if (authenticator == null) {
            if (log.isDebugEnabled()) {
                log.debug("doAuth({}) no authenticator", session);
            }
            return false;
        }

        if (!authenticator.authenticate(getUsername(), key, session)) {
            return Boolean.FALSE;
        }

        if (!hasSig) {
            Buffer buf = session.prepareBuffer(SshConstants.SSH_MSG_USERAUTH_PK_OK, BufferUtils.clear(buffer));
            buf.putString(alg);
            buf.putRawBytes(buffer.array(), oldPos, 4 + len);
            session.writePacket(buf);
            return null;
        } else {
            Buffer buf = new ByteArrayBuffer();
            buf.putBytes(session.getKex().getH());
            buf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            buf.putString(getUsername());
            buf.putString(getService());
            buf.putString(getName());
            buf.putBoolean(true);
            buf.putString(alg);
            buffer.rpos(oldPos);
            buffer.wpos(oldPos + 4 + len);
            buf.putBuffer(buffer);
            verifier.update(buf.array(), buf.rpos(), buf.available());
            if (!verifier.verify(sig)) {
                throw new Exception("Key verification failed");
            }
            return Boolean.TRUE;
        }
    }
}
