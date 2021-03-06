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
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.UserAuthFactory;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Client side <code>ssh-auth</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientUserAuthService extends AbstractCloseable implements Service, ClientSessionHolder {
    /**
     * The AuthFuture that is being used by the current auth request. This encodes the state. isSuccess ->
     * authenticated, else if isDone -> server waiting for user auth, else authenticating.
     */
    protected final AtomicReference<AuthFuture> authFutureHolder = new AtomicReference<>();
    protected final ClientSessionImpl clientSession;
    protected final List<UserAuthFactory> authFactories;
    protected final List<String> clientMethods;
    protected List<String> serverMethods;

    private final Map<String, Object> properties = new ConcurrentHashMap<>();

    private String service;
    private UserAuth userAuth;
    private int currentMethod;

    public ClientUserAuthService(Session s) {
        clientSession = ValidateUtils.checkInstanceOf(
                s, ClientSessionImpl.class, "Client side service used on server side: %s", s);
        authFactories = ValidateUtils.checkNotNullAndNotEmpty(
                clientSession.getUserAuthFactories(), "No user auth factories for %s", s);
        clientMethods = new ArrayList<>();

        String prefs = CoreModuleProperties.PREFERRED_AUTHS.getOrNull(s);
        boolean debugEnabled = log.isDebugEnabled();
        if (GenericUtils.isEmpty(prefs)) {
            for (UserAuthFactory factory : authFactories) {
                clientMethods.add(factory.getName());
            }
        } else {
            if (debugEnabled) {
                log.debug("ClientUserAuthService({}) use configured preferences: {}", s, prefs);
            }

            for (String pref : GenericUtils.split(prefs, ',')) {
                UserAuthFactory factory = NamedResource.findByName(pref, String.CASE_INSENSITIVE_ORDER, authFactories);
                if (factory != null) {
                    clientMethods.add(pref);
                } else {
                    if (debugEnabled) {
                        log.debug("ClientUserAuthService({}) skip unknown preferred authentication method: {}", s, pref);
                    }
                }
            }
        }

        if (debugEnabled) {
            log.debug("ClientUserAuthService({}) client methods: {}", s, clientMethods);
        }

        clientSession.resetAuthTimeout();
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
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    public void start() {
        // ignored
    }

    public String getCurrentServiceName() {
        return service;
    }

    public AuthFuture auth(String service) throws IOException {
        this.service = ValidateUtils.checkNotNullAndNotEmpty(service, "No service name");

        ClientSession session = getClientSession();
        AuthFuture authFuture = updateCurrentAuthFuture(session, service);

        // start from scratch
        serverMethods = null;
        currentMethod = 0;
        if (userAuth != null) {
            try {
                userAuth.destroy();
            } finally {
                userAuth = null;
            }
        }

        sendInitialAuthRequest(session, service);
        return authFuture;
    }

    protected AuthFuture updateCurrentAuthFuture(ClientSession session, String service) throws IOException {
        // check if any previous future in use
        AuthFuture authFuture = createAuthFuture(session, service);
        AuthFuture currentFuture = authFutureHolder.getAndSet(authFuture);
        if (currentFuture != null) {
            if (currentFuture.isDone()) {
                if (log.isDebugEnabled()) {
                    log.debug("updateCurrentAuthFuture({})[{}] request new authentication", session, service);
                }
            } else {
                currentFuture.setException(
                        new InterruptedIOException("New authentication started before previous completed"));
            }
        }

        return authFuture;
    }

    protected AuthFuture createAuthFuture(ClientSession session, String service) throws IOException {
        return new DefaultAuthFuture(service, clientSession.getFutureLock());
    }

    protected IoWriteFuture sendInitialAuthRequest(ClientSession session, String service) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("auth({})[{}] send SSH_MSG_USERAUTH_REQUEST for 'none'", session, service);
        }

        String username = session.getUsername();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST,
                username.length() + service.length() + Integer.SIZE);
        buffer.putString(username);
        buffer.putString(service);
        buffer.putString("none");
        return session.writePacket(buffer);
    }

    @Override
    public void process(int cmd, Buffer buffer) throws Exception {
        ClientSession session = getClientSession();
        AuthFuture authFuture = authFutureHolder.get();
        boolean debugEnabled = log.isDebugEnabled();
        if ((authFuture != null) && authFuture.isSuccess()) {
            log.error("process({}) unexpected authenticated client command: {}",
                    session, SshConstants.getCommandMessageName(cmd));
            throw new IllegalStateException("UserAuth message delivered to authenticated client");
        } else if ((authFuture != null) && authFuture.isDone()) {
            // ignore for now; TODO: random packets
            if (debugEnabled) {
                log.debug("process({}) Ignoring random message - cmd={}",
                        session, SshConstants.getCommandMessageName(cmd));
            }
        } else if (cmd == SshConstants.SSH_MSG_USERAUTH_BANNER) {
            String welcome = buffer.getString();
            String lang = buffer.getString();
            if (debugEnabled) {
                log.debug("process({}) Welcome banner(lang={}): {}", session, lang, welcome);
            }

            UserInteraction ui = session.getUserInteraction();
            try {
                if ((ui != null) && ui.isInteractionAllowed(session)) {
                    ui.welcome(session, welcome, lang);
                }
            } catch (Error e) {
                warn("process({}) failed ({}) to consult interaction: {}",
                        session, e.getClass().getSimpleName(), e.getMessage(), e);
                throw new RuntimeSshException(e);
            }
        } else {
            buffer.rpos(buffer.rpos() - 1);
            processUserAuth(buffer);
        }
    }

    /**
     * Execute one step in user authentication.
     *
     * @param  buffer    The input {@link Buffer}
     * @throws Exception If failed to process
     */
    protected void processUserAuth(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        ClientSession session = getClientSession();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            if (log.isDebugEnabled()) {
                log.debug("processUserAuth({}) SSH_MSG_USERAUTH_SUCCESS Succeeded with {}",
                        session, (userAuth == null) ? "<unknown>" : userAuth.getName());
            }

            if (userAuth != null) {
                try {
                    try {
                        userAuth.signalAuthMethodSuccess(session, service, buffer);
                    } finally {
                        userAuth.destroy();
                    }
                } finally {
                    userAuth = null;
                }
            }
            session.setAuthenticated();
            ((ClientSessionImpl) session).switchToNextService();

            AuthFuture authFuture = Objects.requireNonNull(authFutureHolder.get(), "No current future");
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
                currentMethod = 0;
                if (userAuth != null) {
                    try {
                        try {
                            userAuth.signalAuthMethodFailure(
                                    session, service, partial, Collections.unmodifiableList(serverMethods), buffer);
                        } finally {
                            userAuth.destroy();
                        }
                    } finally {
                        userAuth = null;
                    }
                }
            }

            tryNext(cmd);
            return;
        }

        if (userAuth == null) {
            throw new IllegalStateException(
                    "Received unknown packet: " + SshConstants.getCommandMessageName(cmd));
        }

        if (log.isDebugEnabled()) {
            log.debug("processUserAuth({}) delegate processing of {} to {}",
                    session, SshConstants.getCommandMessageName(cmd), userAuth.getName());
        }

        buffer.rpos(buffer.rpos() - 1);
        if (!userAuth.process(buffer)) {
            tryNext(cmd);
        }
    }

    protected void tryNext(int cmd) throws Exception {
        ClientSession session = getClientSession();
        // Loop until we find something to try
        for (boolean debugEnabled = log.isDebugEnabled();; debugEnabled = log.isDebugEnabled()) {
            if (userAuth == null) {
                if (debugEnabled) {
                    log.debug("tryNext({}) starting authentication mechanisms: client={}, server={}",
                            session, clientMethods, serverMethods);
                }
            } else if (!userAuth.process(null)) {
                if (debugEnabled) {
                    log.debug("tryNext({}) no initial request sent by method={}", session, userAuth.getName());
                }

                try {
                    userAuth.destroy();
                } finally {
                    userAuth = null;
                }

                currentMethod++;
            } else {
                if (debugEnabled) {
                    log.debug("tryNext({}) successfully processed initial buffer by method={}",
                            session, userAuth.getName());
                }
                return;
            }

            String method = null;
            for (; currentMethod < clientMethods.size(); currentMethod++) {
                method = clientMethods.get(currentMethod);
                if (serverMethods.contains(method)) {
                    break;
                }
            }

            if (currentMethod >= clientMethods.size()) {
                if (debugEnabled) {
                    log.debug("tryNext({}) exhausted all methods - client={}, server={}",
                            session, clientMethods, serverMethods);
                }

                // also wake up anyone sitting in waitFor
                AuthFuture authFuture = Objects.requireNonNull(authFutureHolder.get(), "No current future");
                authFuture.setException(new SshException(
                        SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                        "No more authentication methods available"));
                return;
            }

            userAuth = UserAuthMethodFactory.createUserAuth(session, authFactories, method);
            if (userAuth == null) {
                throw new UnsupportedOperationException(
                        "Failed to find a user-auth factory for method=" + method);
            }

            if (debugEnabled) {
                log.debug("tryNext({}) attempting method={}", session, method);
            }

            userAuth.init(session, service);
        }
    }

    @Override
    protected void preClose() {
        AuthFuture authFuture = authFutureHolder.get();
        if ((authFuture != null) && (!authFuture.isDone())) {
            authFuture.setException(new SshException("Session is closed"));
        }

        super.preClose();
    }
}
