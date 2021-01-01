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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesHolder;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Implements the &quot;publickey&quot; authentication mechanism
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey extends AbstractUserAuth implements SignatureFactoriesManager {
    public static final String NAME = UserAuthPublicKeyFactory.NAME;

    protected Iterator<PublicKeyIdentity> keys;
    protected PublicKeyIdentity current;
    protected List<NamedFactory<Signature>> factories;

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
        releaseKeys(); // just making sure in case multiple calls to the method

        try {
            keys = new UserAuthPublicKeyIterator(session, this);
        } catch (Error e) {
            warn("init({})[{}] failed ({}) to initialize session keys: {}",
                    session, service, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        try {
            current = resolveAttemptedPublicKeyIdentity(session, service);
        } catch (Error e) {
            warn("sendAuthDataRequest({})[{}] failed ({}) to get next key: {}",
                    session, service, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        PublicKeyAuthenticationReporter reporter = session.getPublicKeyAuthenticationReporter();
        if (current == null) {
            if (debugEnabled) {
                log.debug("resolveAttemptedPublicKeyIdentity({})[{}] no more keys to send", session, service);
            }

            if (reporter != null) {
                reporter.signalAuthenticationExhausted(session, service);
            }

            return false;
        }

        if (log.isTraceEnabled()) {
            log.trace("sendAuthDataRequest({})[{}] current key details: {}", session, service, current);
        }

        KeyPair keyPair;
        try {
            keyPair = current.getKeyIdentity();
        } catch (Error e) {
            warn("sendAuthDataRequest({})[{}] failed ({}) to retrieve key identity: {}",
                    session, service, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        PublicKey pubKey = keyPair.getPublic();
        String keyType = KeyUtils.getKeyType(pubKey);
        NamedFactory<? extends Signature> factory;
        // SSHD-1104 check if the key type is aliased
        if (current instanceof SignatureFactoriesHolder) {
            factory = SignatureFactory.resolveSignatureFactory(
                    keyType, ((SignatureFactoriesHolder) current).getSignatureFactories());
        } else {
            factory = SignatureFactory.resolveSignatureFactory(keyType, getSignatureFactories());
        }

        String algo = (factory == null) ? keyType : factory.getName();
        String name = getName();
        if (debugEnabled) {
            log.debug("sendAuthDataRequest({})[{}] send SSH_MSG_USERAUTH_REQUEST request {} type={} - fingerprint={}",
                    session, service, name, algo, KeyUtils.getFingerPrint(pubKey));
        }

        if (reporter != null) {
            reporter.signalAuthenticationAttempt(session, service, keyPair, algo);
        }

        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(session.getUsername());
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(false);
        buffer.putString(algo);
        buffer.putPublicKey(pubKey);
        session.writePacket(buffer);
        return true;
    }

    protected PublicKeyIdentity resolveAttemptedPublicKeyIdentity(ClientSession session, String service) throws Exception {
        if ((keys != null) && keys.hasNext()) {
            return keys.next();
        }

        UserInteraction ui = session.getUserInteraction();
        if ((ui == null) || (!ui.isInteractionAllowed(session))) {
            return null;
        }

        KeyPair kp = ui.resolveAuthPublicKeyIdentityAttempt(session);
        if (kp == null) {
            return null;
        }

        return new KeyPairIdentity(this, session, kp);
    }

    @Override
    protected boolean processAuthDataRequest(ClientSession session, String service, Buffer buffer) throws Exception {
        String name = getName();
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            throw new IllegalStateException(
                    "processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                                            + " received unknown packet: cmd=" + SshConstants.getCommandMessageName(cmd));
        }

        /*
         * Make sure the server echo-ed the same key we sent as sanctioned by RFC4252 section 7
         */
        KeyPair keyPair;
        boolean debugEnabled = log.isDebugEnabled();
        try {
            keyPair = current.getKeyIdentity();
        } catch (Error e) {
            warn("processAuthDataRequest({})[{}][{}] failed ({}) to retrieve key identity: {}",
                    session, service, name, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        PublicKey pubKey = keyPair.getPublic();
        String curKeyType = KeyUtils.getKeyType(pubKey);
        String rspKeyType = buffer.getString();
        Collection<String> aliases = KeyUtils.getAllEquivalentKeyTypes(curKeyType);
        String algo;
        // SSHD-1104 see if key aliases used
        if (GenericUtils.isEmpty(aliases)) {
            algo = curKeyType;
            if (!rspKeyType.equals(algo)) {
                throw new InvalidKeySpecException(
                        "processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                                                  + " mismatched key types: expected=" + algo + ", actual=" + rspKeyType);
            }
        } else {
            if (GenericUtils.findFirstMatchingMember(n -> n.equalsIgnoreCase(rspKeyType), aliases) == null) {
                throw new InvalidKeySpecException(
                        "processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                                                  + " unsupported key type: expected=" + aliases + ", actual=" + rspKeyType);
            }
            algo = rspKeyType;
        }

        PublicKey rspKey = buffer.getPublicKey();
        if (!KeyUtils.compareKeys(rspKey, pubKey)) {
            throw new InvalidKeySpecException(
                    "processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                                              + " mismatched " + algo + " keys: expected=" + KeyUtils.getFingerPrint(pubKey)
                                              + ", actual=" + KeyUtils.getFingerPrint(rspKey));
        }

        if (debugEnabled) {
            log.debug("processAuthDataRequest({})[{}][{}] SSH_MSG_USERAUTH_PK_OK type={}, fingerprint={}",
                    session, service, name, rspKeyType, KeyUtils.getFingerPrint(rspKey));
        }

        String username = session.getUsername();
        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                GenericUtils.length(username) + GenericUtils.length(service)
                                                                             + GenericUtils.length(name)
                                                                             + GenericUtils.length(algo)
                                                                             + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(true);
        buffer.putString(algo);
        buffer.putPublicKey(pubKey);

        byte[] sig = appendSignature(session, service, name, username, algo, pubKey, buffer);
        PublicKeyAuthenticationReporter reporter = session.getPublicKeyAuthenticationReporter();
        if (reporter != null) {
            reporter.signalSignatureAttempt(session, service, keyPair, algo, sig);
        }

        session.writePacket(buffer);
        return true;
    }

    protected byte[] appendSignature(
            ClientSession session, String service, String name, String username, String algo, PublicKey key, Buffer buffer)
            throws Exception {
        byte[] id = session.getSessionId();
        Buffer bs = new ByteArrayBuffer(
                id.length + username.length() + service.length() + name.length()
                                        + algo.length() + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE,
                false);
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
            Map.Entry<String, byte[]> result = current.sign(session, algo, contents);
            String factoryName = result.getKey();
            ValidateUtils.checkState(algo.equalsIgnoreCase(factoryName),
                    "Mismatched signature type generated: requested=%s, used=%s", algo, factoryName);
            sig = result.getValue();
        } catch (Error e) {
            warn("appendSignature({})[{}][{}] failed ({}) to sign contents using {}: {}",
                    session, service, name, e.getClass().getSimpleName(), algo, e.getMessage(), e);
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
        return sig;
    }

    @Override
    public void signalAuthMethodSuccess(ClientSession session, String service, Buffer buffer) throws Exception {
        PublicKeyAuthenticationReporter reporter = session.getPublicKeyAuthenticationReporter();
        if (reporter != null) {
            reporter.signalAuthenticationSuccess(session, service, (current == null) ? null : current.getKeyIdentity());
        }
    }

    @Override
    public void signalAuthMethodFailure(
            ClientSession session, String service, boolean partial, List<String> serverMethods, Buffer buffer)
            throws Exception {
        PublicKeyAuthenticationReporter reporter = session.getPublicKeyAuthenticationReporter();
        if (reporter != null) {
            KeyPair identity = (current == null) ? null : current.getKeyIdentity();
            reporter.signalAuthenticationFailure(session, service, identity, partial, serverMethods);
        }
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
