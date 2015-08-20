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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Client side <code>ssh-auth</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientUserAuthService extends CloseableUtils.AbstractCloseable implements Service {

    /**
     * The AuthFuture that is being used by the current auth request.  This encodes the state.
     * isSuccess -> authenticated, else if isDone -> server waiting for user auth, else authenticating.
     */
    private final AuthFuture authFuture;

    private final ClientSessionImpl session;

    private List<Object> identities;
    private String service;

    private List<NamedFactory<UserAuth>> authFactories;
    private List<String> clientMethods;
    private List<String> serverMethods;
    private UserAuth userAuth;

    private int currentMethod;

    public ClientUserAuthService(Session s) {
        if (!(s instanceof ClientSessionImpl)) {
            throw new IllegalStateException("Client side service used on server side");
        }
        session = (ClientSessionImpl) s;
        authFuture = new DefaultAuthFuture(session.getLock());
        ClientFactoryManager manager = session.getFactoryManager();
        authFactories = manager.getUserAuthFactories();
        clientMethods = new ArrayList<>();

        String prefs = FactoryManagerUtils.getString(manager, ClientFactoryManager.PREFERRED_AUTHS);
        if (!GenericUtils.isEmpty(prefs)) {
            for (String pref : prefs.split(",")) {
                NamedFactory<UserAuth> factory = NamedResource.Utils.findByName(pref, String.CASE_INSENSITIVE_ORDER, authFactories);
                if (factory != null) {
                    clientMethods.add(pref);
                } else {
                    log.debug("Skip unknown prefered authentication method: {}", pref);
                }
            }
        } else {
            for (NamedFactory<UserAuth> factory : authFactories) {
                clientMethods.add(factory.getName());
            }
        }
    }

    @Override
    public ClientSessionImpl getSession() {
        return session;
    }

    @Override
    public void start() {
        // ignored
    }

    public AuthFuture auth(List<Object> identities, String service) throws IOException {
        log.debug("Start authentication");
        this.identities = new ArrayList<>(identities);
        this.service = service;

        log.debug("Send SSH_MSG_USERAUTH_REQUEST for none");
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(session.getUsername());
        buffer.putString(service);
        buffer.putString("none");
        session.writePacket(buffer);

        return authFuture;
    }

    @Override
    public void process(int cmd, Buffer buffer) throws Exception {
        if (this.authFuture.isSuccess()) {
            throw new IllegalStateException("UserAuth message delivered to authenticated client");
        } else if (this.authFuture.isDone()) {
            log.debug("Ignoring random message");
            // ignore for now; TODO: random packets
        } else if (cmd == SshConstants.SSH_MSG_USERAUTH_BANNER) {
            String welcome = buffer.getString();
            String lang = buffer.getString();
            log.debug("Welcome banner(lang={}): {}", lang, welcome);
            UserInteraction ui = session.getFactoryManager().getUserInteraction();
            if (ui != null) {
                ui.welcome(welcome);
            }
        } else {
            buffer.rpos(buffer.rpos() - 1);
            processUserAuth(buffer);
        }
    }

    /**
     * execute one step in user authentication.
     *
     * @param buffer
     * @throws java.io.IOException
     */
    private void processUserAuth(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            log.debug("SSH_MSG_USERAUTH_SUCCESS Succeeded with {}", userAuth);
            if (userAuth != null) {
                userAuth.destroy();
                userAuth = null;
            }
            session.setAuthenticated();
            session.switchToNextService();
            // Will wake up anyone sitting in waitFor
            authFuture.setAuthed(true);
            return;
        }
        if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            log.debug("Received SSH_MSG_USERAUTH_FAILURE");
            String mths = buffer.getString();
            boolean partial = buffer.getBoolean();
            if (partial || serverMethods == null) {
                serverMethods = Arrays.asList(mths.split(","));
                if (log.isDebugEnabled()) {
                    StringBuilder sb = new StringBuilder("Authentications that can continue: ");
                    for (int i = 0; i < serverMethods.size(); i++) {
                        if (i > 0) {
                            sb.append(", ");
                        }
                        sb.append(serverMethods.get(i));
                    }
                    log.debug(sb.toString());
                }
                if (userAuth != null) {
                    userAuth.destroy();
                    userAuth = null;
                }
            }
            tryNext();
            return;
        }
        if (userAuth == null) {
            throw new IllegalStateException("Received unknown packet");
        }
        buffer.rpos(buffer.rpos() - 1);
        if (!userAuth.process(buffer)) {
            tryNext();
        }
    }

    private void tryNext() throws Exception {
        // Loop until we find something to try
        while (true) {
            if (userAuth == null) {
                currentMethod = 0;
            } else if (!userAuth.process(null)) {
                userAuth.destroy();
                currentMethod++;
            } else {
                return;
            }
            while (currentMethod < clientMethods.size() && !serverMethods.contains(clientMethods.get(currentMethod))) {
                currentMethod++;
            }
            if (currentMethod >= clientMethods.size()) {
                // Failure
                authFuture.setAuthed(false);
                return;
            }
            String method = clientMethods.get(currentMethod);
            userAuth = NamedFactory.Utils.create(authFactories, method);
            if (userAuth == null) {
                throw new UnsupportedOperationException("Failed to find a user-auth factory for method=" + method);
            }
            userAuth.init(session, service, identities);
        }
    }

    @Override
    protected void preClose() {
        super.preClose();
        if (!authFuture.isDone()) {
            authFuture.setException(new SshException("Session is closed"));
        }
    }

}
