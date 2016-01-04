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
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
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
public class UserAuthPublicKey extends AbstractUserAuth implements SignatureFactoriesManager {
    public static final String NAME = UserAuthPublicKeyFactory.NAME;

    private List<NamedFactory<Signature>> factories;

    public UserAuthPublicKey() {
        this(null);
    }

    public UserAuthPublicKey(List<NamedFactory<Signature>> factories) {
        super(NAME);
        this.factories = factories; // OK if null/empty
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return factories;
    }

    @Override
    public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
        this.factories = factories;
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
        String username = getUsername();
        PublicKey key = buffer.getRawPublicKey();
        Collection<NamedFactory<Signature>> factories =
                ValidateUtils.checkNotNullAndNotEmpty(
                        SignatureFactoriesManager.Utils.resolveSignatureFactories(this, session),
                        "No signature factories for session=%s",
                        session);
        if (log.isDebugEnabled()) {
            log.debug("doAuth({}@{}) verify key type={}, factories={}, fingerprint={}",
                      username, session, alg, NamedResource.Utils.getNames(factories), KeyUtils.getFingerPrint(key));
        }

        Signature verifier = ValidateUtils.checkNotNull(
                NamedFactory.Utils.create(factories, alg),
                "No verifier located for algorithm=%s",
                alg);
        verifier.initVerifier(key);
        buffer.wpos(oldLim);

        byte[] sig = hasSig ? buffer.getBytes() : null;
        PublickeyAuthenticator authenticator = session.getPublickeyAuthenticator();
        if (authenticator == null) {
            if (log.isDebugEnabled()) {
                log.debug("doAuth({}@{}) key type={}, fingerprint={} - no authenticator",
                          username, session, alg, KeyUtils.getFingerPrint(key));
            }
            return false;
        }

        boolean authed = authenticator.authenticate(username, key, session);
        if (log.isDebugEnabled()) {
            log.debug("doAuth({}@{}) key type={}, fingerprint={} - authentication result: {}",
                      username, session, alg, KeyUtils.getFingerPrint(key), authed);
        }
        if (!authed) {
            return Boolean.FALSE;
        }

        if (!hasSig) {
            if (log.isDebugEnabled()) {
                log.debug("doAuth({}@{}) send SSH_MSG_USERAUTH_PK_OK for key type={}, fingerprint={}",
                           username, session, alg, KeyUtils.getFingerPrint(key));
            }

            Buffer buf = session.prepareBuffer(SshConstants.SSH_MSG_USERAUTH_PK_OK, BufferUtils.clear(buffer));
            buf.putString(alg);
            buf.putRawBytes(buffer.array(), oldPos, 4 + len);
            session.writePacket(buf);
            return null;
        }

        // verify signature
        Buffer buf = new ByteArrayBuffer();
        buf.putBytes(session.getKex().getH());
        buf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buf.putString(username);
        buf.putString(getService());
        buf.putString(getName());
        buf.putBoolean(true);
        buf.putString(alg);
        buffer.rpos(oldPos);
        buffer.wpos(oldPos + 4 + len);
        buf.putBuffer(buffer);
        verifier.update(buf.array(), buf.rpos(), buf.available());
        if (log.isTraceEnabled()) {
            log.trace("doAuth({}@{}) key type={}, fingerprint={} - verification data={}",
                      username, session, alg, KeyUtils.getFingerPrint(key), buf.printHex());
            log.trace("doAuth({}@{}) key type={}, fingerprint={} - expected signature={}",
                    username, session, alg, KeyUtils.getFingerPrint(key), BufferUtils.printHex(sig));
        }

        if (!verifier.verify(sig)) {
            throw new Exception("Key verification failed");
        }

        if (log.isDebugEnabled()) {
            log.debug("doAuth({}@{}) key type={}, fingerprint={} - verified",
                      username, session, alg, KeyUtils.getFingerPrint(key));
        }

        return Boolean.TRUE;
    }
}
