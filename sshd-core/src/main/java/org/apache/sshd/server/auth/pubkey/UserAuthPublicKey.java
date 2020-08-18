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
package org.apache.sshd.server.auth.pubkey;

import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.auth.AbstractUserAuth;
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
        ServerSession session = getServerSession();
        String username = getUsername();

        boolean hasSig = buffer.getBoolean();
        String alg = buffer.getString();
        int oldLim = buffer.wpos();
        int oldPos = buffer.rpos();
        int len = buffer.getInt();
        int remaining = buffer.available();
        // Protect against malicious or corrupted packets
        if ((len < 0) || (len > remaining)) {
            log.error("doAuth({}@{}) illogical algorithm={} signature length ({}) when remaining={}",
                    username, session, alg, len, remaining);
            throw new IndexOutOfBoundsException("Illogical signature length (" + len + ") for algorithm=" + alg);
        }

        buffer.wpos(buffer.rpos() + len);

        PublicKey key = buffer.getRawPublicKey();
        Collection<NamedFactory<Signature>> factories = ValidateUtils.checkNotNullAndNotEmpty(
                SignatureFactoriesManager.resolveSignatureFactories(this, session),
                "No signature factories for session=%s",
                session);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doAuth({}@{}) verify key type={}, factories={}, fingerprint={}",
                    username, session, alg, NamedResource.getNames(factories), KeyUtils.getFingerPrint(key));
        }

        Signature verifier = ValidateUtils.checkNotNull(
                NamedFactory.create(factories, alg),
                "No verifier located for algorithm=%s",
                alg);
        verifier.initVerifier(session, key);
        buffer.wpos(oldLim);

        byte[] sig = hasSig ? buffer.getBytes() : null;
        PublickeyAuthenticator authenticator = session.getPublickeyAuthenticator();
        if (authenticator == null) {
            if (debugEnabled) {
                log.debug("doAuth({}@{}) key type={}, fingerprint={} - no authenticator",
                        username, session, alg, KeyUtils.getFingerPrint(key));
            }
            return Boolean.FALSE;
        }

        boolean authed;
        try {
            authed = authenticator.authenticate(username, key, session);
        } catch (Error e) {
            warn("doAuth({}@{}) failed ({}) to consult delegate for {} key={}: {}",
                    username, session, e.getClass().getSimpleName(), alg, KeyUtils.getFingerPrint(key), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        if (debugEnabled) {
            log.debug("doAuth({}@{}) key type={}, fingerprint={} - authentication result: {}",
                    username, session, alg, KeyUtils.getFingerPrint(key), authed);
        }

        if (!authed) {
            return Boolean.FALSE;
        }

        if (!hasSig) {
            sendPublicKeyResponse(session, username, alg, key, buffer.array(), oldPos, 4 + len, buffer);
            return null;
        }

        buffer.rpos(oldPos);
        buffer.wpos(oldPos + 4 + len);
        if (!verifySignature(session, username, alg, key, buffer, verifier, sig)) {
            throw new SignatureException("Key verification failed");
        }

        if (debugEnabled) {
            log.debug("doAuth({}@{}) key type={}, fingerprint={} - verified",
                    username, session, alg, KeyUtils.getFingerPrint(key));
        }

        return Boolean.TRUE;
    }

    protected boolean verifySignature(
            ServerSession session, String username, String alg, PublicKey key, Buffer buffer, Signature verifier, byte[] sig)
            throws Exception {
        byte[] id = session.getSessionId();
        String service = getService();
        String name = getName();
        Buffer buf = new ByteArrayBuffer(
                id.length + username.length() + service.length() + name.length()
                                         + alg.length() + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE,
                false);
        buf.putBytes(id);
        buf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buf.putString(username);
        buf.putString(service);
        buf.putString(name);
        buf.putBoolean(true);
        buf.putString(alg);
        buf.putBuffer(buffer);

        if (log.isTraceEnabled()) {
            log.trace("verifySignature({}@{})[{}][{}] key type={}, fingerprint={} - verification data={}",
                    username, session, service, name, alg, KeyUtils.getFingerPrint(key), buf.toHex());
            log.trace("verifySignature({}@{})[{}][{}] key type={}, fingerprint={} - expected signature={}",
                    username, session, service, name, alg, KeyUtils.getFingerPrint(key), BufferUtils.toHex(sig));
        }

        verifier.update(session, buf.array(), buf.rpos(), buf.available());
        return verifier.verify(session, sig);
    }

    protected void sendPublicKeyResponse(
            ServerSession session, String username, String alg, PublicKey key,
            byte[] keyBlob, int offset, int blobLen, Buffer buffer)
            throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("doAuth({}@{}) send SSH_MSG_USERAUTH_PK_OK for key type={}, fingerprint={}",
                    username, session, alg, KeyUtils.getFingerPrint(key));
        }

        Buffer buf = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_PK_OK,
                GenericUtils.length(alg) + blobLen + Integer.SIZE);
        buf.putString(alg);
        buf.putRawBytes(keyBlob, offset, blobLen);
        session.writePacket(buf);
    }
}
