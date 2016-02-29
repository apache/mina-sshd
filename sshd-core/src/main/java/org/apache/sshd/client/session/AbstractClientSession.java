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
import java.security.PublicKey;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.scp.DefaultScpClient;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.subsystem.sftp.DefaultSftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpFileSystem;
import org.apache.sshd.client.subsystem.sftp.SftpFileSystemProvider;
import org.apache.sshd.client.subsystem.sftp.SftpVersionSelector;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.forward.TcpipForwarder;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.scp.ScpFileOpener;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.helpers.AbstractConnectionService;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * Provides default implementations of {@link ClientSession} related methods
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractClientSession extends AbstractSession implements ClientSession {
    private final List<Object> identities = new CopyOnWriteArrayList<>();
    private final AuthenticationIdentitiesProvider identitiesProvider;
    private ServerKeyVerifier serverKeyVerifier;
    private UserInteraction userInteraction;
    private PasswordIdentityProvider passwordIdentityProvider;
    private List<NamedFactory<UserAuth>> userAuthFactories;
    private ScpTransferEventListener scpListener;
    private ScpFileOpener scpOpener;
    private SocketAddress connectAddress;
    private ClientProxyConnector proxyConnector;

    protected AbstractClientSession(ClientFactoryManager factoryManager, IoSession ioSession) {
        super(false, factoryManager, ioSession);
        identitiesProvider = AuthenticationIdentitiesProvider.Utils.wrap(identities);
    }

    @Override
    public ClientFactoryManager getFactoryManager() {
        return (ClientFactoryManager) super.getFactoryManager();
    }

    @Override
    public SocketAddress getConnectAddress() {
        return resolvePeerAddress(connectAddress);
    }

    public void setConnectAddress(SocketAddress connectAddress) {
        this.connectAddress = connectAddress;
    }

    @Override
    public ServerKeyVerifier getServerKeyVerifier() {
        return resolveEffectiveProvider(ServerKeyVerifier.class, serverKeyVerifier, getFactoryManager().getServerKeyVerifier());
    }

    @Override
    public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = serverKeyVerifier; // OK if null - inherit from parent
    }

    @Override
    public UserInteraction getUserInteraction() {
        return resolveEffectiveProvider(UserInteraction.class, userInteraction, getFactoryManager().getUserInteraction());
    }

    @Override
    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction; // OK if null - inherit from parent
    }

    @Override
    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return resolveEffectiveFactories(UserAuth.class, userAuthFactories, getFactoryManager().getUserAuthFactories());
    }

    @Override
    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = userAuthFactories; // OK if null/empty - inherit from parent
    }

    @Override
    public AuthenticationIdentitiesProvider getRegisteredIdentities() {
        return identitiesProvider;
    }

    @Override
    public PasswordIdentityProvider getPasswordIdentityProvider() {
        return resolveEffectiveProvider(PasswordIdentityProvider.class, passwordIdentityProvider, getFactoryManager().getPasswordIdentityProvider());
    }

    @Override
    public void setPasswordIdentityProvider(PasswordIdentityProvider provider) {
        passwordIdentityProvider = provider;
    }

    @Override
    public ClientProxyConnector getClientProxyConnector() {
        return resolveEffectiveProvider(ClientProxyConnector.class, proxyConnector, getFactoryManager().getClientProxyConnector());
    }

    @Override
    public void setClientProxyConnector(ClientProxyConnector proxyConnector) {
        this.proxyConnector = proxyConnector;
    }

    @Override
    public void addPasswordIdentity(String password) {
        identities.add(ValidateUtils.checkNotNullAndNotEmpty(password, "No password provided"));
        if (log.isDebugEnabled()) { // don't show the password in the log
            log.debug("addPasswordIdentity({}) {}", this, KeyUtils.getFingerPrint(password));
        }
    }

    @Override
    public String removePasswordIdentity(String password) {
        if (GenericUtils.isEmpty(password)) {
            return null;
        }

        int index = AuthenticationIdentitiesProvider.Utils.findIdentityIndex(
                identities, AuthenticationIdentitiesProvider.Utils.PASSWORD_IDENTITY_COMPARATOR, password);
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
            PublicKey key = kp.getPublic();
            log.debug("addPublicKeyIdentity({}) {}-{}",
                      this, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
        }
    }

    @Override
    public KeyPair removePublicKeyIdentity(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        int index = AuthenticationIdentitiesProvider.Utils.findIdentityIndex(
                identities, AuthenticationIdentitiesProvider.Utils.KEYPAIR_IDENTITY_COMPARATOR, kp);
        if (index >= 0) {
            return (KeyPair) identities.remove(index);
        } else {
            return null;
        }
    }

    protected IoWriteFuture sendClientIdentification() throws Exception {
        clientVersion = resolveIdentificationString(ClientFactoryManager.CLIENT_IDENTIFICATION);

        ClientProxyConnector proxyConnector = getClientProxyConnector();
        if (proxyConnector != null) {
            try {
                proxyConnector.sendClientProxyMetadata(this);
            } catch (Throwable t) {
                log.warn("sendClientIdentification({}) failed ({}) to send proxy metadata: {}",
                         this, t.getClass().getSimpleName(), t.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("sendClientIdentification(" + this + ") proxy metadata send failure details", t);
                }

                if (t instanceof Exception) {
                    throw (Exception) t;
                } else {
                    throw new RuntimeSshException(t);
                }
            }
        }

        return sendIdentification(clientVersion);
    }

    @Override
    public ClientChannel createChannel(String type) throws IOException {
        return createChannel(type, null);
    }

    @Override
    public ClientChannel createChannel(String type, String subType) throws IOException {
        if (Channel.CHANNEL_SHELL.equals(type)) {
            return createShellChannel();
        } else if (Channel.CHANNEL_EXEC.equals(type)) {
            return createExecChannel(subType);
        } else if (Channel.CHANNEL_SUBSYSTEM.equals(type)) {
            return createSubsystemChannel(subType);
        } else {
            throw new IllegalArgumentException("Unsupported channel type " + type);
        }
    }

    @Override
    public ChannelExec createExecChannel(String command) throws IOException {
        ChannelExec channel = new ChannelExec(command);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createExecChannel({})[{}] created id={}", this, command, id);
        }
        return channel;
    }

    @Override
    public ChannelSubsystem createSubsystemChannel(String subsystem) throws IOException {
        ChannelSubsystem channel = new ChannelSubsystem(subsystem);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createSubsystemChannel({})[{}] created id={}", this, subsystem, id);
        }
        return channel;
    }

    @Override
    public ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        ChannelDirectTcpip channel = new ChannelDirectTcpip(local, remote);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createDirectTcpipChannel({})[{} => {}] created id={}", this, local, remote, id);
        }
        return channel;
    }

    protected ClientUserAuthService getUserAuthService() {
        return getService(ClientUserAuthService.class);
    }

    protected ConnectionService getConnectionService() {
        return getService(ConnectionService.class);
    }

    @Override
    public ScpFileOpener getScpFileOpener() {
        return resolveEffectiveProvider(ScpFileOpener.class, scpOpener, getFactoryManager().getScpFileOpener());
    }

    @Override
    public void setScpFileOpener(ScpFileOpener opener) {
        scpOpener = opener;
    }

    @Override
    public ScpTransferEventListener getScpTransferEventListener() {
        return scpListener;
    }

    @Override
    public void setScpTransferEventListener(ScpTransferEventListener listener) {
        scpListener = listener;
    }

    @Override   // TODO make this a default method in JDK-8
    public ScpClient createScpClient() {
        return createScpClient(getScpFileOpener(), getScpTransferEventListener());
    }

    @Override   // TODO make this a default method in JDK-8
    public ScpClient createScpClient(ScpTransferEventListener listener) {
        return createScpClient(getScpFileOpener(), listener);
    }

    @Override   // TODO make this a default method in JDK-8
    public ScpClient createScpClient(ScpFileOpener opener) {
        return createScpClient(opener, getScpTransferEventListener());
    }

    @Override
    public ScpClient createScpClient(ScpFileOpener opener, ScpTransferEventListener listener) {
        return new DefaultScpClient(this, opener, listener);
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
        try {
            client.negotiateVersion(selector);
        } catch (IOException | RuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("createSftpClient({}) failed ({}) to negotiate version: {}",
                          this, e.getClass().getSimpleName(), e.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("createSftpClient(" + this + ") version negotiation failure details", e);
            }

            client.close();
            throw e;
        }

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
    protected String resolveAvailableSignaturesProposal(FactoryManager manager) {
        // the client does not have to provide keys for the available signatures
        ValidateUtils.checkTrue(manager == getFactoryManager(), "Mismatched factory manager instances");
        return NamedResource.Utils.getNames(getSignatureFactories());
    }

    @Override
    public void startService(String name) throws Exception {
        throw new IllegalStateException("Starting services is not supported on the client side: " + name);
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
            log.debug("createShellChannel({}) created id={}", this, id);
        }
        return channel;
    }

    @Override
    protected boolean readIdentification(Buffer buffer) throws IOException {
        List<String> ident = doReadIdentification(buffer, false);
        int numLines = GenericUtils.size(ident);
        serverVersion = (numLines <= 0) ? null : ident.remove(numLines - 1);
        if (serverVersion == null) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("readIdentification({}) Server version string: {}", this, serverVersion);
        }

        if (!(serverVersion.startsWith(DEFAULT_SSH_VERSION_PREFIX) || serverVersion.startsWith("SSH-1.99-"))) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                    "Unsupported protocol version: " + serverVersion);
        }

        signalExtraServerVersionInfo(ident);
        return true;
    }

    protected void signalExtraServerVersionInfo(List<String> lines) throws IOException {
        if (GenericUtils.isEmpty(lines)) {
            return;
        }

        UserInteraction ui = getUserInteraction();
        try {
            if ((ui != null) && ui.isInteractionAllowed(this)) {
                ui.serverVersionInfo(this, lines);
            }
        } catch (Error e) {
            log.warn("signalExtraServerVersionInfo({}) failed ({}) to consult interaction: {}",
                     this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("signalExtraServerVersionInfo(" + this + ") interaction consultation failure details", e);
            }

            throw new RuntimeSshException(e);
        }
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
    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
        mergeProposals(serverProposal, proposal);
        i_s = seed;
    }

    @Override
    protected void checkKeys() throws SshException {
        ServerKeyVerifier serverKeyVerifier = ValidateUtils.checkNotNull(getServerKeyVerifier(), "No server key verifier");
        SocketAddress remoteAddress = ioSession.getRemoteAddress();
        PublicKey serverKey = kex.getServerKey();
        boolean verified = serverKeyVerifier.verifyServerKey(this, remoteAddress, serverKey);
        if (log.isDebugEnabled()) {
            log.debug("checkKeys({}) key={}-{}, verified={}",
                      this, KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey), verified);
        }

        if (!verified) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "Server key did not validate");
        }
    }

    @Override
    public KeyExchangeFuture switchToNoneCipher() throws IOException {
        if (!(currentService instanceof AbstractConnectionService<?>)
                || !GenericUtils.isEmpty(((AbstractConnectionService<?>) currentService).getChannels())) {
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
                log.info("switchToNoneCipher({}) switching", this);

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
}
