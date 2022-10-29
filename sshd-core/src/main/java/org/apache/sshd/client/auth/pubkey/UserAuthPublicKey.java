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
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.client.auth.AbstractUserAuth;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler;
import org.apache.sshd.common.kex.extension.parser.HostBoundPubkeyAuthentication;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesHolder;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
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

    /**
     * Is set on a {@link ClientSession} when it is created; if {@link Boolean#FALSE}, no default identities shall be
     * used.
     */
    public static final AttributeKey<Boolean> USE_DEFAULT_IDENTITIES = new AttributeKey<>();

    /**
     * Is set on a {@link ClientSession} when it is created; contains the value of the {@code IdentityAgent} SSH config
     * setting. May be the empty string if not specified in the
     * {@link org.apache.sshd.client.config.hosts.HostConfigEntry#IDENTITY_AGENT HostConfigEntry}.
     */
    public static final AttributeKey<String> IDENTITY_AGENT = new AttributeKey<>();

    protected final Deque<String> currentAlgorithms = new LinkedList<>();

    protected Iterator<PublicKeyIdentity> keys;
    protected PublicKeyIdentity current;
    protected List<NamedFactory<Signature>> factories;
    protected String chosenAlgorithm;

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
            keys = createPublicKeyIterator(session, this);
        } catch (Error e) {
            warn("init({})[{}] failed ({}) to initialize session keys: {}",
                    session, service, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }
    }

    protected Iterator<PublicKeyIdentity> createPublicKeyIterator(ClientSession session, SignatureFactoriesManager manager)
            throws Exception {
        return new UserAuthPublicKeyIterator(session, manager);
    }

    @Override
    protected boolean sendAuthDataRequest(ClientSession session, String service) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        String currentAlgorithm = null;
        if (current == null) {
            // Just to be safe. (Paranoia)
            currentAlgorithms.clear();
            chosenAlgorithm = null;
        } else if (!currentAlgorithms.isEmpty()) {
            currentAlgorithm = currentAlgorithms.poll();
            if (chosenAlgorithm != null) {
                Set<String> knownServerAlgorithms = session.getAttribute(
                        DefaultClientKexExtensionHandler.SERVER_ALGORITHMS);
                if (knownServerAlgorithms != null
                        && knownServerAlgorithms.contains(chosenAlgorithm)) {
                    // We've tried key 'current' with 'chosenAlgorithm', but it
                    // failed. However, the server had told us it supported
                    // 'chosenAlgorithm'. Thus it makes no sense to continue
                    // with this key and other signature algorithms. Skip to the
                    // next key, if any.
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "sendAuthDataRequest({})[{}] server rejected publickey authentication with known signature algorithm {}",
                                session, service, chosenAlgorithm);
                    }
                    currentAlgorithm = null;
                }
            }
        }
        PublicKeyAuthenticationReporter reporter = session.getPublicKeyAuthenticationReporter();
        KeyPair keyPair;
        PublicKey pubKey;
        do {
            if (currentAlgorithm == null) {
                try {
                    current = resolveAttemptedPublicKeyIdentity(session, service, reporter);
                } catch (Error e) {
                    warn("sendAuthDataRequest({})[{}] failed ({}) to get next key: {}", session, service,
                            e.getClass().getSimpleName(), e.getMessage(), e);
                    throw new RuntimeSshException(e);
                }
                currentAlgorithms.clear();
                chosenAlgorithm = null;
                if (current == null) {
                    if (debugEnabled) {
                        log.debug("resolveAttemptedPublicKeyIdentity({})[{}] no more keys to send", session, service);
                    }

                    if (reporter != null) {
                        reporter.signalAuthenticationExhausted(session, service);
                    }

                    return false;
                }
            }
            if (log.isTraceEnabled()) {
                log.trace("sendAuthDataRequest({})[{}] current key details: {}", session, service, current);
            }

            try {
                keyPair = current.getKeyIdentity();
            } catch (Error e) {
                warn("sendAuthDataRequest({})[{}] failed ({}) to retrieve key identity: {}",
                        session, service, e.getClass().getSimpleName(), e.getMessage(), e);
                throw new RuntimeSshException(e);
            }
            pubKey = keyPair.getPublic();

            if (currentAlgorithm == null) {
                String keyType = KeyUtils.getKeyType(pubKey);
                Set<String> aliases = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
                aliases.addAll(KeyUtils.getAllEquivalentKeyTypes(keyType));
                aliases.add(keyType);
                List<NamedFactory<Signature>> existingFactories = null;
                if (current instanceof SignatureFactoriesHolder) {
                    existingFactories = ((SignatureFactoriesHolder) current).getSignatureFactories();
                }
                if (GenericUtils.isEmpty(existingFactories)) {
                    existingFactories = getSignatureFactories();
                }
                if (GenericUtils.isEmpty(existingFactories)) {
                    existingFactories = session.getSignatureFactories();
                }
                if (existingFactories != null) {
                    // Select the factories by name and in order
                    existingFactories.forEach(f -> {
                        if (aliases.contains(f.getName())) {
                            currentAlgorithms.add(f.getName());
                        }
                    });
                }
                currentAlgorithm = currentAlgorithms.poll();
                if (GenericUtils.isEmpty(currentAlgorithm)) {
                    currentAlgorithm = getDefaultSignatureAlgorithm(session, service, current, keyPair, keyType);
                    if (GenericUtils.isEmpty(currentAlgorithm)) {
                        currentAlgorithm = null;
                        if (debugEnabled) {
                            log.debug("sendAuthDataRequest({})[{}] skipping {} key {}; no signature algorithm", session,
                                    service, keyType, KeyUtils.getFingerPrint(pubKey));
                        }
                        if (reporter != null) {
                            reporter.signalIdentitySkipped(session, service, keyPair);
                        }
                    }
                }
            }
        } while (currentAlgorithm == null);

        String name = getName();
        Integer hostBoundPubKeyVersion = session.getAttribute(DefaultClientKexExtensionHandler.HOSTBOUND_AUTHENTICATION);
        boolean doHostBoundAuth = hostBoundPubKeyVersion != null && hostBoundPubKeyVersion.intValue() == 0;
        if (doHostBoundAuth) {
            name = HostBoundPubkeyAuthentication.AUTH_NAME;
        }
        if (debugEnabled) {
            log.debug("sendAuthDataRequest({})[{}] send SSH_MSG_USERAUTH_REQUEST request {} type={} - fingerprint={}",
                    session, service, name, currentAlgorithm, KeyUtils.getFingerPrint(pubKey));
        }

        if (reporter != null) {
            reporter.signalAuthenticationAttempt(session, service, keyPair, currentAlgorithm);
        }

        chosenAlgorithm = currentAlgorithm;
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(session.getUsername());
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(false);
        buffer.putString(currentAlgorithm);
        buffer.putPublicKey(pubKey);
        if (doHostBoundAuth) {
            buffer.putPublicKey(session.getServerKey());
        }
        session.writePacket(buffer);
        return true;
    }

    protected PublicKeyIdentity resolveAttemptedPublicKeyIdentity(ClientSession session, String service) throws Exception {
        return resolveAttemptedPublicKeyIdentity(session, service, null);
    }

    protected PublicKeyIdentity resolveAttemptedPublicKeyIdentity(
            ClientSession session, String service,
            PublicKeyAuthenticationReporter reporter)
            throws Exception {
        if (keys != null) {
            while (keys.hasNext()) {
                PublicKeyIdentity nextKey = keys.next();
                KeyPair identity = nextKey.getKeyIdentity();
                PublicKey pk = identity.getPublic();
                if (pk instanceof OpenSshCertificate) {
                    OpenSshCertificate cert = (OpenSshCertificate) pk;
                    if (!OpenSshCertificate.Type.USER.equals(cert.getType())) {
                        log.warn(
                                "resolveAttemptedPublicKeyIdentity({})[{}]: public key certificate {} {} (id={}) is not a user certificate",
                                session, service, KeyUtils.getKeyType(cert), KeyUtils.getFingerPrint(cert), cert.getId());
                        if (reporter != null) {
                            reporter.signalIdentitySkipped(session, service, identity);
                        }
                        continue;
                    }
                    if (!OpenSshCertificate.isValidNow(cert)) {
                        log.warn(
                                "resolveAttemptedPublicKeyIdentity({})[{}]: public key certificate {} {} (id={}) is not valid now",
                                session, service, KeyUtils.getKeyType(cert), KeyUtils.getFingerPrint(cert), cert.getId());
                        if (reporter != null) {
                            reporter.signalIdentitySkipped(session, service, identity);
                        }
                        continue;
                    }
                }
                return nextKey;
            }
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

    /**
     * Determines a signature algorithm name to use for the authentication request if none could be determined from the
     * installed signature factories. If a non-{@code null} non-empty string is returned, it is used <em>as is</em> in
     * the authentication.
     * <p>
     * This is mainly intended for use with identities from an SSH agent, where the SSH agent may be able to sign the
     * request even if there is no appropriate signature factory present in Java. Whether it makes sense to allow this
     * depends on the application logic and how it handles e.g. SSH config {@code PubkeyAcceptedKeyTypes} (or
     * {@code PubkeyAcceptedAlgorithms}}.
     * </p>
     * <p>
     * This default implementation always returns {@code null}, skipping the key.
     * </p>
     *
     * @param  session   {@link ClientSession} trying to authenticate
     * @param  service   SSH service name
     * @param  identity  {@link PublicKeyIdentity} considered to be used for authentication
     * @param  keyPair   {@link KeyPair} from {@code identity}
     * @param  keyType   the key type of {@code keyPair}
     * @return           {@code null} or an empty string to skip this key and consider another key, if any, to use for
     *                   authentication, or a non-empty signature algorithm name to use for the authentication attempt
     *                   using the given {@code identity}
     * @throws Exception if an error occurs
     * @see              KeyAgentIdentity
     */
    protected String getDefaultSignatureAlgorithm(
            ClientSession session, String service, PublicKeyIdentity identity,
            KeyPair keyPair, String keyType)
            throws Exception {
        return null;
    }

    @Override
    protected boolean processAuthDataRequest(ClientSession session, String service, Buffer buffer) throws Exception {
        String name = getName();
        PublicKey serverKey = null;
        Integer hostBoundPubKeyVersion = session.getAttribute(DefaultClientKexExtensionHandler.HOSTBOUND_AUTHENTICATION);
        boolean doHostBoundAuth = hostBoundPubKeyVersion != null && hostBoundPubKeyVersion.intValue() == 0;
        if (doHostBoundAuth) {
            name = HostBoundPubkeyAuthentication.AUTH_NAME;
            serverKey = session.getServerKey();
        }
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            throw new IllegalStateException("processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
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

        String rspKeyType = buffer.getString();
        PublicKey rspKey = buffer.getPublicKey();

        if (debugEnabled) {
            log.debug("processAuthDataRequest({})[{}][{}] SSH_MSG_USERAUTH_PK_OK type={}, fingerprint={}",
                    session, service, name, rspKeyType, KeyUtils.getFingerPrint(rspKey));
        }
        if (!KeyUtils.compareKeys(rspKey, pubKey)) {
            throw new InvalidKeySpecException("processAuthDataRequest(" + session + ")[" + service + "][" + name + "]"
                                              + " mismatched " + rspKeyType + " keys: expected="
                                              + KeyUtils.getFingerPrint(pubKey)
                                              + ", actual=" + KeyUtils.getFingerPrint(rspKey));
        }

        if (!chosenAlgorithm.equalsIgnoreCase(rspKeyType)) {
            log.warn("processAuthDataRequest({})[{}][{}] sent algorithm {} but got back {} from {}",
                    session, service, name, chosenAlgorithm, rspKeyType, session.getServerVersion());
        }

        String username = session.getUsername();
        String algo = chosenAlgorithm;
        int length = GenericUtils.length(username) + GenericUtils.length(service) + GenericUtils.length(name)
                     + GenericUtils.length(algo) + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE;
        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST, length);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString(name);
        buffer.putBoolean(true);
        buffer.putString(algo);
        buffer.putPublicKey(pubKey);
        if (serverKey != null) {
            buffer.putPublicKey(serverKey);
        }

        if (debugEnabled) {
            log.debug(
                    "processAuthDataRequest({})[{}][{}]: signing with algorithm {}", //$NON-NLS-1$
                    session, service, name, algo);
        }
        byte[] sig = appendSignature(session, service, name, username, algo, pubKey, serverKey, buffer);
        PublicKeyAuthenticationReporter reporter = session.getPublicKeyAuthenticationReporter();
        if (reporter != null) {
            reporter.signalSignatureAttempt(session, service, keyPair, algo, sig);
        }

        session.writePacket(buffer);
        return true;
    }

    protected byte[] appendSignature(
            ClientSession session, String service, String name, String username, String algo, PublicKey key,
            PublicKey serverKey, Buffer buffer)
            throws Exception {
        byte[] id = session.getSessionId();
        int length = id.length + username.length() + service.length() + name.length() + algo.length()
                     + ByteArrayBuffer.DEFAULT_SIZE + Long.SIZE;
        Buffer bs = new ByteArrayBuffer(length, false);
        bs.putBytes(id);
        bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        bs.putString(username);
        bs.putString(service);
        bs.putString(name);
        bs.putBoolean(true);
        bs.putString(algo);
        bs.putPublicKey(key);
        if (serverKey != null) {
            bs.putPublicKey(serverKey);
        }

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

        String signatureAlgo = KeyUtils.getSignatureAlgorithm(algo, key);

        if (log.isTraceEnabled()) {
            log.trace("appendSignature({})[{}] name={}, key type={}, fingerprint={} - verification data={}",
                    session, service, name, signatureAlgo, KeyUtils.getFingerPrint(key), BufferUtils.toHex(contents));
            log.trace("appendSignature({})[{}] name={}, key type={}, fingerprint={} - generated signature={}",
                    session, service, name, signatureAlgo, KeyUtils.getFingerPrint(key), BufferUtils.toHex(sig));
        }

        bs.clear();
        bs.putString(signatureAlgo);
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
        currentAlgorithms.clear();
        current = null;
        chosenAlgorithm = null;
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
