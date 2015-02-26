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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.ScpClient;
import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.UserInteraction;
import org.apache.sshd.client.auth.deprecated.UserAuth;
import org.apache.sshd.client.auth.deprecated.UserAuthAgent;
import org.apache.sshd.client.auth.deprecated.UserAuthKeyboardInteractive;
import org.apache.sshd.client.auth.deprecated.UserAuthPassword;
import org.apache.sshd.client.auth.deprecated.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.client.scp.DefaultScpClient;
import org.apache.sshd.client.sftp.DefaultSftpClient;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientSessionImpl extends AbstractSession implements ClientSession {

    /**
     * For clients to store their own metadata
     */
    private Map<Object, Object> metadataMap = new HashMap<Object, Object>();

    // TODO: clean service support a bit
    private boolean initialServiceRequestSent;
    private ServiceFactory currentServiceFactory;
    private Service nextService;
    private ServiceFactory nextServiceFactory;
    private final List<Object> identities = new ArrayList<Object>();
    private UserInteraction userInteraction;

    protected AuthFuture authFuture;

    public ClientSessionImpl(ClientFactoryManager client, IoSession session) throws Exception {
        super(false, client, session);
        log.info("Client session created");
        // Need to set the initial service early as calling code likes to start trying to
        // manipulate it before the connection has even been established.  For instance, to
        // set the authPassword.
        List<ServiceFactory> factories = client.getServiceFactories();
        if (factories == null || factories.isEmpty() || factories.size() > 2) {
            throw new IllegalArgumentException("One or two services must be configured");
        }
        currentServiceFactory = factories.get(0);
        currentService = currentServiceFactory.create(this);
        if (factories.size() > 1) {
            nextServiceFactory = factories.get(1);
            nextService = nextServiceFactory.create(this);
        } else {
            nextServiceFactory = null;
        }
        authFuture = new DefaultAuthFuture(lock);
        authFuture.setAuthed(false);
        sendClientIdentification();
        kexState.set(KEX_STATE_INIT);
        sendKexInit();
    }

    protected Service[] getServices() {
        Service[] services;
        if (nextService != null) {
            services = new Service[] { currentService, nextService };
        } else if (currentService != null) {
            services = new Service[] { currentService };
        } else {
            services = new Service[0];
        }
        return services;
    }

    public ClientFactoryManager getFactoryManager() {
        return (ClientFactoryManager) factoryManager;
    }

    public void addPasswordIdentity(String password) {
        identities.add(password);
    }

    public void addPublicKeyIdentity(KeyPair key) {
        identities.add(key);
    }

    public UserInteraction getUserInteraction() {
        return userInteraction;
    }

    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction;
    }

    public AuthFuture auth() throws IOException {
        if (username == null) {
            throw new IllegalStateException("No username specified when the session was created");
        }
        synchronized (lock) {
            return authFuture = getUserAuthService().auth(identities, nextServiceName());
        }
    }

    public AuthFuture authAgent(String user) throws IOException {
        return tryAuth(user, new UserAuthAgent(this, nextServiceName()));
    }

    public AuthFuture authPassword(String user, String password) throws IOException {
        return tryAuth(user, new UserAuthPassword(this, nextServiceName(), password));
    }

    public AuthFuture authInteractive(String user, String password) throws IOException {
        return tryAuth(user, new UserAuthKeyboardInteractive(this, nextServiceName(), password));
   }

    public AuthFuture authPublicKey(String user, KeyPair key) throws IOException {
        return tryAuth(user, new UserAuthPublicKey(this, nextServiceName(), key));
    }

    private AuthFuture tryAuth(String user, UserAuth auth) throws IOException {
        this.username = user;
        synchronized (lock) {
            return authFuture = getUserAuthService().auth(auth);
        }
    }

    private String nextServiceName() {
        synchronized (lock) {
            return nextServiceFactory.getName();
        }
    }

    protected void switchToNextService() throws IOException {
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

    public SshFuture switchToNoneCipher() throws IOException {
        if (!(currentService instanceof AbstractConnectionService)
                || !((AbstractConnectionService) currentService).getChannels().isEmpty()) {
            throw new IllegalStateException("The switch to the none cipher must be done immediately after authentication");
        }
        if (kexState.compareAndSet(KEX_STATE_DONE, KEX_STATE_INIT)) {
            reexchangeFuture = new DefaultSshFuture(null);
            if (!serverProposal[SshConstants.PROPOSAL_ENC_ALGS_CTOS].matches("(^|.*,)none($|,.*)")
                    || !serverProposal[SshConstants.PROPOSAL_ENC_ALGS_STOC].matches("(^|.*,)none($|,.*)")) {
                reexchangeFuture.setValue(new SshException("Server does not support none cipher"));
            } else if (!clientProposal[SshConstants.PROPOSAL_ENC_ALGS_CTOS].matches("(^|.*,)none($|,.*)")
                    || !clientProposal[SshConstants.PROPOSAL_ENC_ALGS_STOC].matches("(^|.*,)none($|,.*)")) {
                reexchangeFuture.setValue(new SshException("Client does not support none cipher"));
            } else {
                log.info("Switching to none cipher");
                clientProposal[SshConstants.PROPOSAL_ENC_ALGS_CTOS] = "none";
                clientProposal[SshConstants.PROPOSAL_ENC_ALGS_STOC] = "none";
                I_C = sendKexInit(clientProposal);
            }
            return reexchangeFuture;
        } else {
            throw new SshException("In flight key exchange");
        }
    }

    public ClientChannel createChannel(String type) throws IOException {
        return createChannel(type, null);
    }

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

    public ChannelShell createShellChannel() throws IOException {
        if (inCipher instanceof CipherNone || outCipher instanceof CipherNone) {
            throw new IllegalStateException("Interactive channels are not supported with none cipher");
        }
        ChannelShell channel = new ChannelShell();
        getConnectionService().registerChannel(channel);
        return channel;
    }

    public ChannelExec createExecChannel(String command) throws IOException {
        ChannelExec channel = new ChannelExec(command);
        getConnectionService().registerChannel(channel);
        return channel;
    }

    public ChannelSubsystem createSubsystemChannel(String subsystem) throws IOException {
        ChannelSubsystem channel = new ChannelSubsystem(subsystem);
        getConnectionService().registerChannel(channel);
        return channel;
    }

    public ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        ChannelDirectTcpip channel = new ChannelDirectTcpip(local, remote);
        getConnectionService().registerChannel(channel);
        return channel;
    }

    private ClientUserAuthService getUserAuthService() {
        return getService(ClientUserAuthService.class);
    }

    private ConnectionService getConnectionService() {
        return getService(ConnectionService.class);
    }

    public ScpClient createScpClient() {
        return new DefaultScpClient(this);
    }

    public SftpClient createSftpClient() throws IOException {
        return new DefaultSftpClient(this);
    }

    public SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        return getConnectionService().getTcpipForwarder().startLocalPortForwarding(local, remote);
    }

    public void stopLocalPortForwarding(SshdSocketAddress local) throws IOException {
        getConnectionService().getTcpipForwarder().stopLocalPortForwarding(local);
    }

    public SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException {
        return getConnectionService().getTcpipForwarder().startRemotePortForwarding(remote, local);
    }

    public void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
        getConnectionService().getTcpipForwarder().stopRemotePortForwarding(remote);
    }

    public SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        return getConnectionService().getTcpipForwarder().startDynamicPortForwarding(local);
    }

    public void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        getConnectionService().getTcpipForwarder().stopDynamicPortForwarding(local);
    }

    protected void handleMessage(Buffer buffer) throws Exception {
        synchronized (lock) {
            super.handleMessage(buffer);
        }
    }

    public int waitFor(int mask, long timeout) {
        long t = 0;
        synchronized (lock) {
            for (;;) {
                int cond = 0;
                if (closeFuture.isClosed()) {
                    cond |= ClientSession.CLOSED;
                }
                if (authed) { // authFuture.isSuccess()
                    cond |= AUTHED;
                }
                if (kexState.get() == KEX_STATE_DONE && authFuture.isFailure()) {
                    cond |= WAIT_AUTH;
                }
                if ((cond & mask) != 0) {
                    return cond;
                }
                if (timeout > 0) {
                    if (t == 0) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0) {
                            cond |= TIMEOUT;
                            return cond;
                        }
                    }
                }
                try {
                    if (timeout > 0) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }
    }

    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer, false);
        if (serverVersion == null) {
            return false;
        }
        log.info("Server version string: {}", serverVersion);
        if (!(serverVersion.startsWith("SSH-2.0-") || serverVersion.startsWith("SSH-1.99-"))) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                                   "Unsupported protocol version: " + serverVersion);
        }
        return true;
    }

    private void sendClientIdentification() {
        clientVersion = "SSH-2.0-" + getFactoryManager().getVersion();
        sendIdentification(clientVersion);
    }

    protected void sendKexInit() throws IOException {
        String algs = NamedFactory.Utils.getNames(getFactoryManager().getSignatureFactories());
        clientProposal = createProposal(algs);
        I_C = sendKexInit(clientProposal);
    }

    protected void receiveKexInit(Buffer buffer) throws IOException {
        serverProposal = new String[SshConstants.PROPOSAL_MAX];
        I_S = receiveKexInit(buffer, serverProposal);
    }

    @Override
    protected void checkKeys() throws SshException {
        ServerKeyVerifier serverKeyVerifier = getFactoryManager().getServerKeyVerifier();
        SocketAddress remoteAddress = ioSession.getRemoteAddress();

        if (!serverKeyVerifier.verifyServerKey(this, remoteAddress, kex.getServerKey())) {
            throw new SshException("Server key did not validate");
        }
    }

    @Override
    protected void sendEvent(SessionListener.Event event) throws IOException {
        if (event == SessionListener.Event.KeyEstablished) {
            sendInitialServiceRequest();
        }
        synchronized (lock) {
            lock.notifyAll();
        }
        super.sendEvent(event);
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
        throw new IllegalStateException("Starting services is not supported on the client side");
    }

    public Map<Object, Object> getMetadataMap() {
		return metadataMap;
	}

}
