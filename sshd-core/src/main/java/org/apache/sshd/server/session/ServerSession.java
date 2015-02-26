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
package org.apache.sshd.server.session;

import java.io.IOException;
import java.security.KeyPair;
import java.util.List;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.ServerFactoryManager;

/**
 *
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerSession extends AbstractSession {

    protected static final long MAX_PACKETS = (1l << 31);

    private long maxBytes = 1024 * 1024 * 1024;   // 1 GB
    private long maxKeyInterval = 60 * 60 * 1000; // 1 hour

    public ServerSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(true, server, ioSession);
        maxBytes = Math.max(32, getLongProperty(ServerFactoryManager.REKEY_BYTES_LIMIT, maxBytes));
        maxKeyInterval = getLongProperty(ServerFactoryManager.REKEY_TIME_LIMIT, maxKeyInterval);
        log.info("Server session created from {}", ioSession.getRemoteAddress());
        sendServerIdentification();
    }

    public String getNegotiated(int index) {
        return negotiated[index];
    }

    public ServerFactoryManager getFactoryManager() {
        return (ServerFactoryManager) factoryManager;
    }

    protected void checkKeys() {
    }

    public void startService(String name) throws Exception {
        currentService = ServiceFactory.Utils.create(getFactoryManager().getServiceFactories(), name, this);
    }

    @Override
    protected void serviceAccept() throws IOException {
        // TODO: can services be initiated by the server-side ?
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Unsupported packet: SSH_MSG_SERVICE_ACCEPT");
    }

    protected void checkRekey() throws IOException {
        if (kexState.get() == KEX_STATE_DONE) {
            if (   inPackets > MAX_PACKETS || outPackets > MAX_PACKETS
                || inBytes > maxBytes || outBytes > maxBytes
                || maxKeyInterval > 0 && System.currentTimeMillis() - lastKeyTime > maxKeyInterval)
            {
                reExchangeKeys();
            }
        }
    }

    private void sendServerIdentification() {
        if (getFactoryManager().getProperties() != null && getFactoryManager().getProperties().get(ServerFactoryManager.SERVER_IDENTIFICATION) != null) {
            serverVersion = "SSH-2.0-" + getFactoryManager().getProperties().get(ServerFactoryManager.SERVER_IDENTIFICATION);
        } else {
            serverVersion = "SSH-2.0-" + getFactoryManager().getVersion();
        }
        sendIdentification(serverVersion);
    }

    protected void sendKexInit() throws IOException {
    	/*
    	 * Make sure that the provided host keys have at least one supported signature factory
    	 */
        FactoryManager manager = getFactoryManager();
        KeyPairProvider kpp = manager.getKeyPairProvider();
        String hostKeyTypes = kpp.getKeyTypes();
        List<String> supported = NamedFactory.Utils.getNameList(manager.getSignatureFactories());
        String[] provided = hostKeyTypes.split(",");
        StringBuilder resolvedHostKeys = null;
        for (int index = 0; index < provided.length; index++) {
            String keyType = provided[index];
            if (!supported.contains(keyType)) {
                if (log.isDebugEnabled()) {
                    log.debug("sendKexInit(" + hostKeyTypes + ") " + keyType + " not in list of supported: " + supported);
                }
    			// Use 1st unsupported key type as trigger to create a new list
                if (resolvedHostKeys == null) {
                    resolvedHostKeys = new StringBuilder(hostKeyTypes.length());
                    // copy all provided key types up to this index - we know they are supported
                    for (int supportedIndex = 0; supportedIndex < index; supportedIndex++) {
                        if (supportedIndex > 0) {
                            resolvedHostKeys.append(',');
                        }
                        resolvedHostKeys.append(provided[supportedIndex]);
                    }
                }
                continue;
            }
            if (resolvedHostKeys != null) {
                if (resolvedHostKeys.length() > 0) {
                    resolvedHostKeys.append(',');
                }
                resolvedHostKeys.append(keyType);
            }
        }

        // check if had to construct a new list
        if (resolvedHostKeys != null) {
            // make sure the new list has at least one supported AND provided key type
            if (resolvedHostKeys.length() <= 0) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
                        "sendKexInit(" + hostKeyTypes + ") none of the keys appears in supported list: " + supported);
            }

            hostKeyTypes = resolvedHostKeys.toString();
        }

        serverProposal = createProposal(hostKeyTypes);
        I_S = sendKexInit(serverProposal);
    }

    protected boolean readIdentification(Buffer buffer) throws IOException {
        clientVersion = doReadIdentification(buffer, true);
        if (clientVersion == null) {
            return false;
        }
        log.debug("Client version string: {}", clientVersion);
        if (!clientVersion.startsWith("SSH-2.0-")) {
            String msg = "Unsupported protocol version: " + clientVersion;
            ioSession.write(new Buffer((msg + "\n").getBytes())).addListener(new SshFutureListener<IoWriteFuture>() {
                public void operationComplete(IoWriteFuture future) {
                    close(true);
                }
            });
            throw new SshException(msg);
        } else {
            kexState.set(KEX_STATE_INIT);
            sendKexInit();
        }
        return true;
    }

    protected void receiveKexInit(Buffer buffer) throws IOException {
        clientProposal = new String[SshConstants.PROPOSAL_MAX];
        I_C = receiveKexInit(buffer, clientProposal);
    }

    public KeyPair getHostKey() {
        return factoryManager.getKeyPairProvider().loadKey(negotiated[SshConstants.PROPOSAL_SERVER_HOST_KEY_ALGS]);
    }

    /**
     * Retrieve the current number of sessions active for a given username.
     * @param userName The name of the user
     * @return The current number of live <code>SshSession</code> objects associated with the user
     */
    protected int getActiveSessionCountForUser(String userName) {
        int totalCount = 0;
        for (IoSession is : ioSession.getService().getManagedSessions().values()) {
            ServerSession session = (ServerSession) getSession(is, true);
            if (session != null) {
                if (session.getUsername() != null && session.getUsername().equals(userName)) {
                    totalCount++;
                }
            }
        }
        return totalCount;
    }

	/**
	 * Returns the session id.
	 * 
	 * @return The session id.
	 */
	public long getId() {
		return ioSession.getId();
	}
}
