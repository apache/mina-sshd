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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.file.FileSystem;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.UserInteraction;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.scp.DefaultScpClient;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.subsystem.sftp.DefaultSftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpFileSystem;
import org.apache.sshd.client.subsystem.sftp.SftpFileSystemProvider;
import org.apache.sshd.client.subsystem.sftp.SftpVersionSelector;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.forward.TcpipForwarder;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientSessionImpl extends AbstractSession implements ClientSession {
    /**
     * Compares 2 password identities - returns zero ONLY if <U>both</U> compared
     * objects are {@link String}s and equal to each other
     */
    public static final Comparator<Object> PASSWORD_IDENTITY_COMPARATOR = new Comparator<Object>() {
        @Override
        public int compare(Object o1, Object o2) {
            if (!(o1 instanceof String) || !(o2 instanceof String)) {
                return -1;
            } else {
                return ((String) o1).compareTo((String) o2);
            }
        }
    };

    /**
     * Compares 2 {@link KeyPair} identities - returns zero ONLY if <U>both</U> compared
     * objects are {@link KeyPair}s and equal to each other
     */
    public static final Comparator<Object> KEYPAIR_IDENTITY_COMPARATOR = new Comparator<Object>() {
        @Override
        public int compare(Object o1, Object o2) {
            if ((!(o1 instanceof KeyPair)) || (!(o2 instanceof KeyPair))) {
                return -1;
            } else if (KeyUtils.compareKeyPairs((KeyPair) o1, (KeyPair) o2)) {
                return 0;
            } else {
                return 1;
            }
        }
    };

    protected AuthFuture authFuture;

    /**
     * For clients to store their own metadata
     */
    private Map<Object, Object> metadataMap = new HashMap<>();

    // TODO: clean service support a bit
    private boolean initialServiceRequestSent;
    private ServiceFactory currentServiceFactory;
    private Service nextService;
    private ServiceFactory nextServiceFactory;
    private final List<Object> identities = new ArrayList<>();
    private UserInteraction userInteraction;
    private ScpTransferEventListener scpListener;
    private KeyPairProvider keyPairProvider;

    public ClientSessionImpl(ClientFactoryManager client, IoSession session) throws Exception {
        super(false, client, session);
        log.debug("Client session created: {}", session);
        // Need to set the initial service early as calling code likes to start trying to
        // manipulate it before the connection has even been established.  For instance, to
        // set the authPassword.
        List<ServiceFactory> factories = client.getServiceFactories();
        int numFactories = GenericUtils.size(factories);
        ValidateUtils.checkTrue((numFactories > 0) && (numFactories <= 2), "One or two services must be configured: %d", numFactories);

        currentServiceFactory = factories.get(0);
        currentService = currentServiceFactory.create(this);
        if (numFactories > 1) {
            nextServiceFactory = factories.get(1);
            nextService = nextServiceFactory.create(this);
        } else {
            nextServiceFactory = null;
        }

        authFuture = new DefaultAuthFuture(lock);
        authFuture.setAuthed(false);
        sendClientIdentification();
        kexState.set(KexState.INIT);
        sendKexInit();
    }

    @Override
    protected Service[] getServices() {
        Service[] services;
        if (nextService != null) {
            services = new Service[]{currentService, nextService};
        } else if (currentService != null) {
            services = new Service[]{currentService};
        } else {
            services = new Service[0];
        }
        return services;
    }

    @Override
    public ClientFactoryManager getFactoryManager() {
        return (ClientFactoryManager) super.getFactoryManager();
    }

    @Override
    public KeyPairProvider getKeyPairProvider() {
        return keyPairProvider;
    }

    public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
        this.keyPairProvider = keyPairProvider;
    }

    @Override
    public void addPasswordIdentity(String password) {
        identities.add(ValidateUtils.checkNotNullAndNotEmpty(password, "No password provided"));
        if (log.isDebugEnabled()) { // don't show the password in the log
            log.debug("addPasswordIdentity(" + KeyUtils.getFingerPrint(password) + ")");
        }
    }

    @Override
    public String removePasswordIdentity(String password) {
        if (GenericUtils.isEmpty(password)) {
            return null;
        }

        int index = findIdentityIndex(PASSWORD_IDENTITY_COMPARATOR, password);
        if (index >= 0) {
            return (String) identities.remove(index);
        } else {
            return null;
        }
    }

    @Override
    public void addPublicKeyIdentity(KeyPair kp) {
        ValidateUtils.checkNotNull(kp, "No key-pair to add");
        ValidateUtils.checkNotNull(kp.getPublic(), "No public key");
        ValidateUtils.checkNotNull(kp.getPrivate(), "No private key");

        identities.add(kp);

        if (log.isDebugEnabled()) {
            log.debug("addPublicKeyIdentity(" + KeyUtils.getFingerPrint(kp.getPublic()) + ")");
        }
    }

    @Override
    public KeyPair removePublicKeyIdentity(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        int index = findIdentityIndex(KEYPAIR_IDENTITY_COMPARATOR, kp);
        if (index >= 0) {
            return (KeyPair) identities.remove(index);
        } else {
            return null;
        }
    }

    protected int findIdentityIndex(Comparator<? super Object> comp, Object target) {
        for (int index = 0; index < identities.size(); index++) {
            Object value = identities.get(index);
            if (comp.compare(value, target) == 0) {
                return index;
            }
        }

        return -1;
    }

    @Override
    public UserInteraction getUserInteraction() {
        return userInteraction;
    }

    @Override
    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction;
    }

    @Override
    public AuthFuture auth() throws IOException {
        if (username == null) {
            throw new IllegalStateException("No username specified when the session was created");
        }

        ClientUserAuthService authService = getUserAuthService();
        synchronized (lock) {
            authFuture = authService.auth(identities, nextServiceName());
            return authFuture;
        }
    }

    private String nextServiceName() {
        synchronized (lock) {
            return nextServiceFactory.getName();
        }
    }

    public void switchToNextService() throws IOException {
        synchronized (lock) {
            if (nextService == null) {
                throw new IllegalStateException("No service available");
            }
            currentServiceFactory = nextServiceFactory;
            currentService = nextService;
            nextServiceFactory = null;
            nextService = null;
            currentService.start();
        }
    }

    @Override
    public KeyExchangeFuture switchToNoneCipher() throws IOException {
        if (!(currentService instanceof AbstractConnectionService)
                || !((AbstractConnectionService) currentService).getChannels().isEmpty()) {
            throw new IllegalStateException("The switch to the none cipher must be done immediately after authentication");
        }

        if (kexState.compareAndSet(KexState.DONE, KexState.INIT)) {
            DefaultKeyExchangeFuture kexFuture = new DefaultKeyExchangeFuture(null);
            DefaultKeyExchangeFuture prev = kexFutureHolder.getAndSet(kexFuture);
            if (prev != null) {
                synchronized (prev) {
                    Object value = prev.getValue();
                    if (value == null) {
                        prev.setValue(new SshException("Switch to none cipher while previous KEX is ongoing"));
                    }
                }
            }

            String c2sEncServer;
            String s2cEncServer;
            synchronized (serverProposal) {
                c2sEncServer = serverProposal.get(KexProposalOption.C2SENC);
                s2cEncServer = serverProposal.get(KexProposalOption.S2CENC);
            }
            boolean c2sEncServerNone = BuiltinCiphers.Constants.isNoneCipherIncluded(c2sEncServer);
            boolean s2cEncServerNone = BuiltinCiphers.Constants.isNoneCipherIncluded(s2cEncServer);

            String c2sEncClient;
            String s2cEncClient;
            synchronized (clientProposal) {
                c2sEncClient = clientProposal.get(KexProposalOption.C2SENC);
                s2cEncClient = clientProposal.get(KexProposalOption.S2CENC);
            }

            boolean c2sEncClientNone = BuiltinCiphers.Constants.isNoneCipherIncluded(c2sEncClient);
            boolean s2cEncClientNone = BuiltinCiphers.Constants.isNoneCipherIncluded(s2cEncClient);

            if ((!c2sEncServerNone) || (!s2cEncServerNone)) {
                kexFuture.setValue(new SshException("Server does not support none cipher"));
            } else if ((!c2sEncClientNone) || (!s2cEncClientNone)) {
                kexFuture.setValue(new SshException("Client does not support none cipher"));
            } else {
                log.info("Switching to none cipher");

                Map<KexProposalOption, String> proposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
                synchronized (clientProposal) {
                    proposal.putAll(clientProposal);
                }

                proposal.put(KexProposalOption.C2SENC, BuiltinCiphers.Constants.NONE);
                proposal.put(KexProposalOption.S2CENC, BuiltinCiphers.Constants.NONE);

                byte[] seed = sendKexInit(proposal);
                setKexSeed(seed);
            }

            return ValidateUtils.checkNotNull(kexFutureHolder.get(), "No current KEX future");
        } else {
            throw new SshException("In flight key exchange");
        }
    }

    @Override
    public ClientChannel createChannel(String type) throws IOException {
        return createChannel(type, null);
    }

    @Override
    public ClientChannel createChannel(String type, String subType) throws IOException {
        if (ClientChannel.CHANNEL_SHELL.equals(type)) {
            return createShellChannel();
        } else if (ClientChannel.CHANNEL_EXEC.equals(type)) {
            return createExecChannel(subType);
        } else if (ClientChannel.CHANNEL_SUBSYSTEM.equals(type)) {
            return createSubsystemChannel(subType);
        } else {
            throw new IllegalArgumentException("Unsupported channel type " + type);
        }
    }

    @Override
    public ChannelShell createShellChannel() throws IOException {
        if ((inCipher instanceof CipherNone) || (outCipher instanceof CipherNone)) {
            throw new IllegalStateException("Interactive channels are not supported with none cipher");
        }
        ChannelShell channel = new ChannelShell();
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createShellChannel(id={}) created", Integer.valueOf(id));
        }
        return channel;
    }

    @Override
    public ChannelExec createExecChannel(String command) throws IOException {
        ChannelExec channel = new ChannelExec(command);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createExecChannel(id={})[{}] created", Integer.valueOf(id), command);
        }
        return channel;
    }

    @Override
    public ChannelSubsystem createSubsystemChannel(String subsystem) throws IOException {
        ChannelSubsystem channel = new ChannelSubsystem(subsystem);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createSubsystemChannel(id={})[{}] created", Integer.valueOf(id), subsystem);
        }
        return channel;
    }

    @Override
    public ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        ChannelDirectTcpip channel = new ChannelDirectTcpip(local, remote);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createDirectTcpipChannel(id={})[{} => {}] created", Integer.valueOf(id), local, remote);
        }
        return channel;
    }

    private ClientUserAuthService getUserAuthService() {
        return getService(ClientUserAuthService.class);
    }

    private ConnectionService getConnectionService() {
        return getService(ConnectionService.class);
    }

    @Override
    public ScpTransferEventListener getScpTransferEventListener() {
        return scpListener;
    }

    @Override
    public void setScpTransferEventListener(ScpTransferEventListener listener) {
        scpListener = listener;
    }

    @Override
    public ScpClient createScpClient() {
        return createScpClient(getScpTransferEventListener());
    }

    @Override
    public ScpClient createScpClient(ScpTransferEventListener listener) {
        return new DefaultScpClient(this, listener);
    }

    @Override   // TODO make this a default method in JDK-8
    public SftpClient createSftpClient() throws IOException {
        return createSftpClient(SftpVersionSelector.CURRENT);
    }

    @Override   // TODO make this a default method in JDK-8
    public SftpClient createSftpClient(final int version) throws IOException {
        return createSftpClient(SftpVersionSelector.Utils.fixedVersionSelector(version));
    }

    @Override
    public SftpClient createSftpClient(SftpVersionSelector selector) throws IOException {
        DefaultSftpClient client = new DefaultSftpClient(this);
        client.negotiateVersion(selector);
        return client;
    }

    @Override
    public FileSystem createSftpFileSystem() throws IOException {
        return createSftpFileSystem(SftpVersionSelector.CURRENT);
    }

    @Override
    public FileSystem createSftpFileSystem(int version) throws IOException {
        return createSftpFileSystem(SftpVersionSelector.Utils.fixedVersionSelector(version));
    }

    @Override
    public FileSystem createSftpFileSystem(SftpVersionSelector selector) throws IOException {
        return createSftpFileSystem(selector, SftpClient.DEFAULT_READ_BUFFER_SIZE, SftpClient.DEFAULT_WRITE_BUFFER_SIZE);
    }

    @Override
    public FileSystem createSftpFileSystem(int version, int readBufferSize, int writeBufferSize) throws IOException {
        return createSftpFileSystem(SftpVersionSelector.Utils.fixedVersionSelector(version), readBufferSize, writeBufferSize);
    }

    @Override
    public FileSystem createSftpFileSystem(int readBufferSize, int writeBufferSize) throws IOException {
        return createSftpFileSystem(SftpVersionSelector.CURRENT, readBufferSize, writeBufferSize);
    }

    @Override
    public FileSystem createSftpFileSystem(SftpVersionSelector selector, int readBufferSize, int writeBufferSize) throws IOException {
        SftpFileSystemProvider provider = new SftpFileSystemProvider((org.apache.sshd.client.SshClient) getFactoryManager(), selector);
        SftpFileSystem fs = provider.newFileSystem(this);
        fs.setReadBufferSize(readBufferSize);
        fs.setWriteBufferSize(writeBufferSize);
        return fs;
    }

    @Override
    public SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        return getTcpipForwarder().startLocalPortForwarding(local, remote);
    }

    @Override
    public void stopLocalPortForwarding(SshdSocketAddress local) throws IOException {
        getTcpipForwarder().stopLocalPortForwarding(local);
    }

    @Override
    public SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException {
        return getTcpipForwarder().startRemotePortForwarding(remote, local);
    }

    @Override
    public void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
        getTcpipForwarder().stopRemotePortForwarding(remote);
    }

    @Override
    public SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        return getTcpipForwarder().startDynamicPortForwarding(local);
    }

    @Override
    public void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        getTcpipForwarder().stopDynamicPortForwarding(local);
    }

    protected TcpipForwarder getTcpipForwarder() {
        ConnectionService service = ValidateUtils.checkNotNull(getConnectionService(), "No connection service");
        return ValidateUtils.checkNotNull(service.getTcpipForwarder(), "No forwarder");
    }

    @Override
    protected void handleMessage(Buffer buffer) throws Exception {
        synchronized (lock) {
            super.handleMessage(buffer);
        }
    }

    @Override
    public Set<ClientSessionEvent> waitFor(Collection<ClientSessionEvent> mask, long timeout) {
        ValidateUtils.checkNotNull(mask, "No mask specified");
        long t = 0L;
        synchronized (lock) {
            for (Set<ClientSessionEvent> cond = EnumSet.noneOf(ClientSessionEvent.class);; cond.clear()) {
                if (closeFuture.isClosed()) {
                    cond.add(ClientSessionEvent.CLOSED);
                }
                if (authed) { // authFuture.isSuccess()
                    cond.add(ClientSessionEvent.AUTHED);
                }
                if (KexState.DONE.equals(kexState.get()) && authFuture.isFailure()) {
                    cond.add(ClientSessionEvent.WAIT_AUTH);
                }

                boolean nothingInCommon = Collections.disjoint(cond, mask);
                if (!nothingInCommon) {
                    if (log.isTraceEnabled()) {
                        log.trace("WaitFor call returning on session {}, mask={}, cond={}",
                                  this, mask, cond);
                    }
                    return cond;
                }

                if (timeout > 0L) {
                    if (t == 0L) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0L) {
                            if (log.isTraceEnabled()) {
                                log.trace("WaitFor call timeout on session {}, mask={}", this, mask);
                            }
                            cond.add(ClientSessionEvent.TIMEOUT);
                            return cond;
                        }
                    }
                }

                if (log.isTraceEnabled()) {
                    log.trace("Waiting {} millis for lock on session {}, mask={}, cond={}", timeout, this, mask, cond);
                }

                long nanoStart = System.nanoTime();
                try {
                    if (timeout > 0) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }

                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (log.isTraceEnabled()) {
                        log.trace("Lock notified on session {} after {} nanos", this, nanoDuration);
                    }
                } catch (InterruptedException e) {
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (log.isTraceEnabled()) {
                        log.trace("waitFor({}) mask={} - ignoring interrupted exception after {} nanos", this, mask, nanoDuration);
                    }
                }
            }
        }
    }

    @Override
    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer, false);
        if (serverVersion == null) {
            return false;
        }
        log.debug("Server version string: {}", serverVersion);
        if (!(serverVersion.startsWith("SSH-2.0-") || serverVersion.startsWith("SSH-1.99-"))) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                    "Unsupported protocol version: " + serverVersion);
        }
        return true;
    }

    protected void sendClientIdentification() {
        FactoryManager manager = getFactoryManager();
        clientVersion = DEFAULT_SSH_VERSION_PREFIX + manager.getVersion();
        sendIdentification(clientVersion);
    }

    @Override
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws IOException {
        mergeProposals(clientProposal, proposal);
        return super.sendKexInit(proposal);
    }

    @Override
    protected void setKexSeed(byte... seed) {
        i_c = ValidateUtils.checkNotNullAndNotEmpty(seed, "No KEX seed");
    }

    @Override
    protected String resolveAvailableSignaturesProposal(FactoryManager manager) {
        // the client does not have to provide keys for the available signatures
        return NamedResource.Utils.getNames(manager.getSignatureFactories());
    }

    @Override
    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
        mergeProposals(serverProposal, proposal);
        i_s = seed;
    }

    @Override
    protected void checkKeys() throws SshException {
        ClientFactoryManager manager = getFactoryManager();
        ServerKeyVerifier serverKeyVerifier = manager.getServerKeyVerifier();
        SocketAddress remoteAddress = ioSession.getRemoteAddress();

        if (!serverKeyVerifier.verifyServerKey(this, remoteAddress, kex.getServerKey())) {
            throw new SshException("Server key did not validate");
        }
    }

    @Override
    protected void sendSessionEvent(SessionListener.Event event) throws IOException {
        if (event == SessionListener.Event.KeyEstablished) {
            sendInitialServiceRequest();
        }
        synchronized (lock) {
            lock.notifyAll();
        }
        super.sendSessionEvent(event);
    }

    protected void sendInitialServiceRequest() throws IOException {
        if (initialServiceRequestSent) {
            return;
        }
        initialServiceRequestSent = true;
        log.debug("Send SSH_MSG_SERVICE_REQUEST for {}", currentServiceFactory.getName());
        Buffer request = createBuffer(SshConstants.SSH_MSG_SERVICE_REQUEST);
        request.putString(currentServiceFactory.getName());
        writePacket(request);
        // Assuming that MINA-SSHD only implements "explicit server authentication" it is permissible
        // for the client's service to start sending data before the service-accept has been received.
        // If "implicit authentication" were to ever be supported, then this would need to be
        // called after service-accept comes back.  See SSH-TRANSPORT.
        currentService.start();
    }

    @Override
    public void startService(String name) throws Exception {
        throw new IllegalStateException("Starting services is not supported on the client side: " + name);
    }

    @Override
    public Map<Object, Object> getMetadataMap() {
        return metadataMap;
    }
}
