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

import org.apache.sshd.client.ClientAuthenticationManager;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * Client side <code>ssh-auth</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientUserAuthService extends AbstractCloseable implements Service, ClientSessionHolder {

    /**
     * The AuthFuture that is being used by the current auth request.  This encodes the state.
     * isSuccess -> authenticated, else if isDone -> server waiting for user auth, else authenticating.
     */
    private final AuthFuture authFuture;

    private final ClientSessionImpl clientSession;

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
        clientSession = (ClientSessionImpl) s;
        authFuture = new DefaultAuthFuture(clientSession.getLock());
        authFactories = clientSession.getUserAuthFactories();
        clientMethods = new ArrayList<>();

        String prefs = PropertyResolverUtils.getString(s, ClientAuthenticationManager.PREFERRED_AUTHS);
        if (GenericUtils.isEmpty(prefs)) {
            for (NamedFactory<UserAuth> factory : authFactories) {
                clientMethods.add(factory.getName());
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("ClientUserAuthService({}) use configured preferrences: {}", s, prefs);
            }

            for (String pref : GenericUtils.split(prefs, ',')) {
                NamedFactory<UserAuth> factory = NamedResource.Utils.findByName(pref, String.CASE_INSENSITIVE_ORDER, authFactories);
                if (factory != null) {
                    clientMethods.add(pref);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("ClientUserAuthService({}) skip unknown preferred authentication method: {}", s, pref);
                    }
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("ClientUserAuthService({}) client methods: {}", s, clientMethods);
        }
    }

    @Override
    public ClientSession getSession() {
        return getClientSession();
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public void start() {
        // ignored
    }

    public AuthFuture auth(List<Object> identities, String service) throws IOException {
        this.identities = new ArrayList<>(identities);
        this.service = service;

        ClientSession session = getClientSession();
        String username = session.getUsername();
        if (log.isDebugEnabled()) {
            log.debug("auth({})[{}] Send SSH_MSG_USERAUTH_REQUEST for 'none'", session, service);
        }

        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST, username.length() + service.length() + Integer.SIZE);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString("none");
        session.writePacket(buffer);

        return authFuture;
    }

    @Override
    public void process(int cmd, Buffer buffer) throws Exception {
        ClientSession session = getClientSession();
        if (this.authFuture.isSuccess()) {
            throw new IllegalStateException("UserAuth message delivered to authenticated client");
        } else if (this.authFuture.isDone()) {
            if (log.isDebugEnabled()) {
                log.debug("process({}) Ignoring random message - cmd={}",
                          session, SshConstants.getCommandMessageName(cmd));
            }
            // ignore for now; TODO: random packets
        } else if (cmd == SshConstants.SSH_MSG_USERAUTH_BANNER) {
            String welcome = buffer.getString();
            String lang = buffer.getString();
            if (log.isDebugEnabled()) {
                log.debug("process({}) Welcome banner(lang={}): {}", session, lang, welcome);
            }

            UserInteraction ui = session.getUserInteraction();
            if ((ui != null) && ui.isInteractionAllowed(session)) {
                ui.welcome(session, welcome, lang);
            }
        } else {
            buffer.rpos(buffer.rpos() - 1);
            processUserAuth(buffer);
        }
    }

    /**
     * Execute one step in user authentication.
     *
     * @param buffer The input {@link Buffer}
     * @throws Exception If failed to process
     */
    protected void processUserAuth(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        ClientSession session = getClientSession();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            if (log.isDebugEnabled()) {
                log.debug("processUserAuth({}) SSH_MSG_USERAUTH_SUCCESS Succeeded with {}",
                          session, userAuth);
            }
            if (userAuth != null) {
                try {
                    userAuth.destroy();
                } finally {
                    userAuth = null;
                }
            }
            session.setAuthenticated();
            ((ClientSessionImpl) session).switchToNextService();
            // Will wake up anyone sitting in waitFor
            authFuture.setAuthed(true);
            return;
        }

        if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            String mths = buffer.getString();
            boolean partial = buffer.getBoolean();
            if (log.isDebugEnabled()) {
                log.debug("processUserAuth({}) Received SSH_MSG_USERAUTH_FAILURE - partial={}, methods={}",
                          session, partial, mths);
            }
            if (partial || (serverMethods == null)) {
                serverMethods = Arrays.asList(GenericUtils.split(mths, ','));
                if (userAuth != null) {
                    try {
                        userAuth.destroy();
                    } finally {
                        userAuth = null;
                    }
                }
            }
            tryNext();
            return;
        }

        if (userAuth == null) {
            throw new IllegalStateException("Received unknown packet: " + SshConstants.getCommandMessageName(cmd));
        }

        buffer.rpos(buffer.rpos() - 1);
        if (!userAuth.process(buffer)) {
            tryNext();
        }
    }

    protected void tryNext() throws Exception {
        ClientSession session = getClientSession();
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
                if (log.isDebugEnabled()) {
                    log.debug("tryNext({}) exhausted all methods - client={}, server={}",
                              session, clientMethods, serverMethods);
                }

                // also wake up anyone sitting in waitFor
                authFuture.setException(new SshException(SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "No more authentication methods available"));
                return;
            }

            String method = clientMethods.get(currentMethod);
            userAuth = NamedFactory.Utils.create(authFactories, method);
            if (userAuth == null) {
                throw new UnsupportedOperationException("Failed to find a user-auth factory for method=" + method);
            }
            if (log.isDebugEnabled()) {
                log.debug("tryNext({}) attempting method={}", session, method);
            }

            userAuth.init(session, service, identities);
        }
    }

    @Override
    protected void preClose() {
        if (!authFuture.isDone()) {
            authFuture.setException(new SshException("Session is closed"));
        }

        super.preClose();
    }
}
