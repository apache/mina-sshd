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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.ScpClient;
import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthAgent;
import org.apache.sshd.client.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.client.scp.DefaultScpClient;
import org.apache.sshd.client.sftp.DefaultSftpClient;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.io.IoSession;
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

    private ServiceFactory currentServiceFactory;

    private Service nextService;
    private ServiceFactory nextServiceFactory;

    protected AuthFuture authFuture;

    public ClientSessionImpl(ClientFactoryManager client, IoSession session) throws Exception {
        super(client, session);
        log.info("Session created...");
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
        sendKexInit();
    }

    public ClientFactoryManager getClientFactoryManager() {
        return (ClientFactoryManager) factoryManager;
    }

    public AuthFuture authAgent(String user) throws IOException {
        return tryAuth(new UserAuthAgent(this, nextServiceName(), user));
    }

    public AuthFuture authPassword(String user, String password) throws IOException {
        return tryAuth(new UserAuthPassword(this, nextServiceName(), user, password));
    }

    public AuthFuture authInteractive(String user, String password) throws IOException {
        return tryAuth(new UserAuthKeyboardInteractive(this, nextServiceName(), user, password));
   }

    public AuthFuture authPublicKey(String user, KeyPair key) throws IOException {
        return tryAuth(new UserAuthPublicKey(this, nextServiceName(), user, key));
    }

    private AuthFuture tryAuth(UserAuth auth) throws IOException {
        synchronized (lock) {
            return authFuture = getUserAuthService().auth(auth);
        }
    }

    private String nextServiceName() {
        return nextServiceFactory.getName();
    }

    protected void switchToNextService() throws IOException {
        if (nextService == null) {
            throw new IllegalStateException("No service available");
        }
        currentServiceFactory = nextServiceFactory;
        currentService = nextService;
        nextServiceFactory = null;
        nextService = null;
        currentService.start();
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
        return findService(ClientUserAuthService.class);
    }

    private ConnectionService getConnectionService() {
        return findService(ConnectionService.class);
    }

    private <T> T findService(Class<T> clazz) {
        if (clazz.isInstance(currentService)) {
            return clazz.cast(currentService);
        }
        if (clazz.isInstance(nextService)) {
            return clazz.cast(nextService);
        }
        throw new IllegalStateException("Attempted to access unknown service " + clazz.getSimpleName());
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

    protected void handleMessage(Buffer buffer) throws Exception {
        synchronized (lock) {
            doHandleMessage(buffer);
        }
    }

    protected void doHandleMessage(Buffer buffer) throws Exception {
        SshConstants.Message cmd = buffer.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                close(true);
                break;
            }
            case SSH_MSG_UNIMPLEMENTED: {
                int code = buffer.getInt();
                log.info("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG: {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_IGNORE:
                log.info("Received SSH_MSG_IGNORE");
                break;
            default:
                switch (getState()) {
                    case ReceiveKexInit:
                        if (cmd != SshConstants.Message.SSH_MSG_KEXINIT) {
                            log.error("Ignoring command {} while waiting for {}", cmd, SshConstants.Message.SSH_MSG_KEXINIT);
                            break;
                        }
                        log.info("Received SSH_MSG_KEXINIT");
                        receiveKexInit(buffer);
                        negociate();
                        kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), negociated[SshConstants.PROPOSAL_KEX_ALGS]);
                        kex.init(this, serverVersion.getBytes(), clientVersion.getBytes(), I_S, I_C);
                        setState(State.Kex);
                        break;
                    case Kex:
                        buffer.rpos(buffer.rpos() - 1);
                        if (kex.next(buffer)) {
                            checkHost();
                            sendNewKeys();
                            setState(State.ReceiveNewKeys);
                        }
                        break;
                    case ReceiveNewKeys:
                        if (cmd != SshConstants.Message.SSH_MSG_NEWKEYS) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_NEWKEYS");
                        receiveNewKeys(false);
                        log.info("Send SSH_MSG_SERVICE_REQUEST for {}", currentServiceFactory.getName());
                        Buffer request = createBuffer(SshConstants.Message.SSH_MSG_SERVICE_REQUEST, 0);
                        request.putString(currentServiceFactory.getName());
                        writePacket(request);
                        setState(State.ServiceRequestSent);
                        // Assuming that MINA-SSHD only implements "explicit server authentication" it is permissible
                        // for the client's service to start sending data before the service-accept has been received.
                        // If "implicit authentication" were to ever be supported, then this would need to be
                        // called after service-accept comes back.  See SSH-TRANSPORT.
                        currentService.start();
                        break;
                    case ServiceRequestSent:
                        if (cmd != SshConstants.Message.SSH_MSG_SERVICE_ACCEPT) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet SSH_MSG_SERVICE_ACCEPT, got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_SERVICE_ACCEPT");
                        setState(State.Running);
                        break;
                    case Running:
                        switch (cmd) {
                            case SSH_MSG_REQUEST_SUCCESS:
                                requestSuccess(buffer);
                                break;
                            case SSH_MSG_REQUEST_FAILURE:
                                requestFailure(buffer);
                                break;
                            default:
                                currentService.process(cmd, buffer);
                                break;
                        }
                        break;
                    default:
                        throw new IllegalStateException("Unsupported state: " + getState());
                }
        }
    }

    public int waitFor(int mask, long timeout) {
        long t = 0;
        synchronized (lock) {
            for (;;) {
                int cond = 0;
                if (closeFuture.isClosed()) {
                    cond |= CLOSED;
                }
                if (authed) { // authFuture.isSuccess()
                    cond |= AUTHED;
                }
                if (authFuture.isFailure()) {
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

    public void setState(State newState) {
        synchronized (lock) {
            super.setState(newState);
            lock.notifyAll();
        }
    }

    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer);
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

    private void sendKexInit() throws Exception {
        clientProposal = createProposal(KeyPairProvider.SSH_RSA + "," + KeyPairProvider.SSH_DSS);
        I_C = sendKexInit(clientProposal);
    }

    private void receiveKexInit(Buffer buffer) throws Exception {
        serverProposal = new String[SshConstants.PROPOSAL_MAX];
        I_S = receiveKexInit(buffer, serverProposal);
    }

    private void checkHost() throws SshException {
        ServerKeyVerifier serverKeyVerifier = getClientFactoryManager().getServerKeyVerifier();
        SocketAddress remoteAddress = ioSession.getRemoteAddress();

        if (!serverKeyVerifier.verifyServerKey(this, remoteAddress, kex.getServerKey())) {
            throw new SshException("Server key did not validate");
        }
    }

	public Map<Object, Object> getMetadataMap() {
		return metadataMap;
	}

}
