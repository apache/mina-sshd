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
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
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

        try {
            keys = new UserAuthPublicKeyIterator(session, this);
        } catch (Error e) {
            log.warn("init({})[{}] failed ({}) to initialize session keys: {}",
                     session, service, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("init(" + session + ")[" + service + "] session keys initialization failure details", e);
            }

            throw new RuntimeSshException(e);
        }
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        try {
            if ((keys == null) || (!keys.hasNext())) {
                if (log.isDebugEnabled()) {
                    log.debug("sendAuthDataRequest({})[{}] no more keys to send", session, service);
                }

                return false;
            }

            current = keys.next();
        } catch (Error e) {
            log.warn("sendAuthDataRequest({})[{}] failed ({}) to get next key: {}",
                     session, service, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("sendAuthDataRequest(" + session + ")[" + service + "] next key fetch failure details", e);
            }

            throw new RuntimeSshException(e);
        }

        if (log.isTraceEnabled()) {
            log.trace("sendAuthDataRequest({})[{}] current key details: {}", session, service, current);
        }

        PublicKey key;
        try {
            key = current.getPublicKey();
        } catch (Error e) {
            log.warn("sendAuthDataRequest({})[{}] failed ({}) to retrieve public key: {}",
                     session, service, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("sendAuthDataRequest(" + session + ")[" + service + "] public key retrieval failure details", e);
            }

            throw new RuntimeSshException(e);
        }
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
        String name = getName();
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            throw new IllegalStateException("processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                    + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
        }

        /*
         * Make sure the server echo-ed the same key we sent as
         * sanctioned by RFC4252 section 7
         */
        PublicKey key;
        try {
            key = current.getPublicKey();
        } catch (Error e) {
            log.warn("processAuthDataRequest({})[{}][{}] failed ({}) to retrieve public key: {}",
                     session, service, name, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("processAuthDataRequest(" + session + ")[" + service + "][" + name + "] public key retrieval failure details", e);
            }

            throw new RuntimeSshException(e);
        }
        String algo = KeyUtils.getKeyType(key);
        String rspKeyType = buffer.getString();
        if (!rspKeyType.equals(algo)) {
            throw new InvalidKeySpecException("processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                    + " mismatched key types: expected=" + algo + ", actual=" + rspKeyType);
        }

        PublicKey rspKey = buffer.getPublicKey();
        if (!KeyUtils.compareKeys(rspKey, key)) {
            throw new InvalidKeySpecException("processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                    + " mismatched " + algo + " keys: expected=" + KeyUtils.getFingerPrint(key) + ", actual=" + KeyUtils.getFingerPrint(rspKey));
        }

        if (log.isDebugEnabled()) {
            log.debug("processAuthDataRequest({})[{}][{}] SSH_MSG_USERAUTH_PK_OK type={}, fingerprint={}",
                      session, service, name, rspKeyType, KeyUtils.getFingerPrint(rspKey));
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
        appendSignature(session, service, name, username, algo, key, buffer);
        session.writePacket(buffer);
        return true;
    }

    protected void appendSignature(ClientSession session, String service, String name, String username, String algo, PublicKey key, Buffer buffer) throws Exception {
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

        byte[] contents = bs.getCompactData();
        byte[] sig;
        try {
            sig = current.sign(contents);
        } catch (Error e) {
            log.warn("appendSignature({})[{}][{}] failed ({}) to sign contents: {}",
                     session, service, name, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("appendSignature(" + session + ")[" + service + "][" + name + "] signing failure details", e);
            }

            throw new RuntimeSshException(e);
        }

        if (log.isTraceEnabled()) {
            log.trace("appendSignature({})[{}] name={}, key type={}, fingerprint={} - verification data={}",
                      session, service, name, algo, KeyUtils.getFingerPrint(key), BufferUtils.toHex(contents));
            log.trace("appendSignature({})[{}] name={}, key type={}, fingerprint={} - generated signature={}",
                      session, service, name, algo, KeyUtils.getFingerPrint(key), BufferUtils.toHex(sig));
        }

        bs.clear();
        bs.putString(algo);
        bs.putBytes(sig);
        buffer.putBytes(bs.array(), bs.rpos(), bs.available());
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
