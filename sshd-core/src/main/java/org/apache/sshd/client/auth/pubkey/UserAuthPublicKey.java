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
package org.apache.sshd.client.auth.pubkey;

import java.io.Closeable;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Implements the &quot;publickey&quot; authentication mechanism
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey extends AbstractUserAuth implements SignatureFactoriesManager {
    public static final String NAME = UserAuthPublicKeyFactory.NAME;

    private Iterator<PublicKeyIdentity> keys;
    private PublicKeyIdentity current;
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
    public void init(ClientSession session, String service) throws Exception {
        super.init(session, service);
        releaseKeys();  // just making sure in case multiple calls to the method
        keys = new UserAuthPublicKeyIterator(session, this);
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        if ((keys == null) || (!keys.hasNext())) {
            if (log.isDebugEnabled()) {
                log.debug("sendAuthDataRequest({})[{}] no more keys to send", session, service);
            }

            return false;
        }

        current = keys.next();
        if (log.isTraceEnabled()) {
            log.trace("sendAuthDataRequest({})[{}] current key details: {}", session, service, current);
        }

        PublicKey key = current.getPublicKey();
        String algo = KeyUtils.getKeyType(key);
        String name = getName();
        if (log.isDebugEnabled()) {
            log.debug("sendAuthDataRequest({})[{}] send SSH_MSG_USERAUTH_REQUEST request {} type={} - fingerprint={}",
                      session, service, name, algo, KeyUtils.getFingerPrint(key));
        }
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(session.getUsername());
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(false);
        buffer.putString(algo);
        buffer.putPublicKey(key);
        session.writePacket(buffer);
        return true;
    }

    @Override
    protected boolean processAuthDataRequest(ClientSession session, String service, Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            throw new IllegalStateException("processAuthDataRequest(" + session + ")[" + service + "]"
                    + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
        }

        PublicKey key = current.getPublicKey();
        String algo = KeyUtils.getKeyType(key);
        String name = getName();
        if (log.isDebugEnabled()) {
            log.debug("processAuthDataRequest({})[{}] send SSH_MSG_USERAUTH_PK_OK reply {} type={} - fingerprint={}",
                      session, service, name, algo, KeyUtils.getFingerPrint(key));
        }

        String username = session.getUsername();
        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                GenericUtils.length(username) + GenericUtils.length(service)
              + GenericUtils.length(name) + GenericUtils.length(algo)
              + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(true);
        buffer.putString(algo);
        buffer.putPublicKey(key);

        byte[] id = session.getSessionId();
        Buffer bs = new ByteArrayBuffer(id.length + username.length() + service.length() + name.length()
            + algo.length() + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE, false);
        bs.putBytes(id);
        bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        bs.putString(username);
        bs.putString(service);
        bs.putString(name);
        bs.putBoolean(true);
        bs.putString(algo);
        bs.putPublicKey(key);

        byte[] sig = current.sign(bs.getCompactData());
        bs = new ByteArrayBuffer(algo.length() + sig.length + Long.SIZE, false);
        bs.putString(algo);
        bs.putBytes(sig);
        buffer.putBytes(bs.array(), bs.rpos(), bs.available());

        session.writePacket(buffer);
        return true;
    }

    @Override
    public void destroy() {
        try {
            releaseKeys();
        } catch (IOException e) {
            throw new RuntimeException("Failed (" + e.getClass().getSimpleName() + ") to close agent: " + e.getMessage(), e);
        }

        super.destroy(); // for logging
    }

    protected void releaseKeys() throws IOException {
        try {
            if (keys instanceof Closeable) {
                if (log.isTraceEnabled()) {
                    log.trace("releaseKeys({}) closing {}", getClientSession(), keys);
                }
                ((Closeable) keys).close();
            }
        } finally {
            keys = null;
        }
    }
}
