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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.UserAuthFactory;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKey;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.future.DefaultCancelFuture;
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
     * The AuthFuture that is being used by the current auth request. It is set while an authentication is ongoing.
     */
    protected final AtomicReference<AuthFuture> authFutureHolder = new AtomicReference<>();
    protected final ClientSessionImpl clientSession;
    protected final List<UserAuthFactory> authFactories;
    protected final List<String> clientMethods;
    protected List<String> serverMethods;

    private final Map<String, Object> properties = new ConcurrentHashMap<>();

    private String service;
    private UserAuth currentUserAuth;
    private int currentMethod;
    private UserAuth pubkeyAuth;

    private final Object initLock = new Object();
    private boolean started;
    private Runnable initialRequestSender;

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
        Runnable initial;
        synchronized (initLock) {
            started = true;
            initial = initialRequestSender;
            initialRequestSender = null;
        }
        if (initial != null) {
            initial.run();
        }
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
        pubkeyAuth = null;
        currentMethod = 0;
        clearUserAuth();

        Runnable sender = () -> {
            try {
                sendInitialAuthRequest(session, service);
            } catch (Exception e) {
                authFuture.setException(e);
            }
        };
        synchronized (initLock) {
            if (!started) {
                initialRequestSender = sender;
                sender = null;
            }
        }
        if (sender != null) {
            sender.run();
        }
        return authFuture;
    }

    protected AuthFuture updateCurrentAuthFuture(ClientSession session, String service) throws IOException {
        // check if any previous future in use
        AuthFuture authFuture = createAuthFuture(session, service);
        if (!authFutureHolder.compareAndSet(null, authFuture)) {
            throw new SshException("Authentication already ongoing");
        }
        return authFuture;
    }

    protected AuthFuture createAuthFuture(ClientSession session, String service) throws IOException {
        return new DefaultAuthFuture(service, clientSession.getFutureLock()) {

            private void clear() {
                authFutureHolder.compareAndSet(this, null);
            }

            @Override
            protected void onValueSet(Object value) {
                if (!(value instanceof CancelFuture)) {
                    clear();
                }
            }

            @Override
            protected CancelFuture createCancellation() {
                return new DefaultCancelFuture(getId()) {

                    @Override
                    protected void onValueSet(Object value) {
                        clear();
                    }
                };
            }
        };
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
        if (authFuture != null) {
            if (authFuture.isSuccess()) {
                log.error("process({}) unexpected authenticated client command: {}",
                        session, SshConstants.getCommandMessageName(cmd));
                throw new IllegalStateException("UserAuth message delivered to authenticated client");
            } else if (authFuture.isCanceled()) {
                return;
            } else if (authFuture.isDone()) {
                // ignore for now; TODO: random packets
                if (debugEnabled) {
                    log.debug("process({}) Ignoring random message - cmd={}", session, SshConstants.getCommandMessageName(cmd));
                }
                return;
            }
        }
        if (cmd == SshConstants.SSH_MSG_USERAUTH_BANNER) {
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
                RuntimeSshException ex = new RuntimeSshException(e);
                if (authFuture != null) {
                    authFuture.setException(ex);
                }
                throw ex;
            }
        } else if (authFuture != null) {
            processUserAuth(cmd, buffer, authFuture);
        } else if (debugEnabled) {
            // authFuture == null
            log.debug("process({}) Ignoring random message - cmd={}", session, SshConstants.getCommandMessageName(cmd));
        }
    }

    /**
     * Execute one step in user authentication.
     *
     * @param  cmd        the command
     * @param  buffer     the input {@link Buffer}, with the reading position after the command byte
     * @param  authFuture the {@link AuthFuture}
     * @throws Exception  If failed to process
     */
    protected void processUserAuth(int cmd, Buffer buffer, AuthFuture authFuture) throws Exception {
        ClientSession session = getClientSession();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            if (log.isDebugEnabled()) {
                log.debug("processUserAuth({}) SSH_MSG_USERAUTH_SUCCESS Succeeded with {}",
                        session, (currentUserAuth == null) ? "<unknown>" : currentUserAuth.getName());
            }

            if (currentUserAuth != null) {
                try {
                    currentUserAuth.signalAuthMethodSuccess(session, service, buffer);
                } finally {
                    clearUserAuth();
                }
            } else {
                destroyPubkeyAuth();
            }
            session.setAuthenticated();
            ((ClientSessionImpl) session).switchToNextService();

            // Will wake up anyone sitting in waitFor
            authFuture.setAuthed(true);
            return;
        }

        authFuture.setCancellable(true);
        if (authFuture.isCanceled()) {
            authFuture.getCancellation().setCanceled();
            clearUserAuth();
            return;
        }
        if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            String methods = buffer.getString();
            boolean partial = buffer.getBoolean();
            if (log.isDebugEnabled()) {
                log.debug("processUserAuth({}) Received SSH_MSG_USERAUTH_FAILURE - partial={}, methods={}",
                        session, partial, methods);
            }
            List<String> allowedMethods;
            if (GenericUtils.isEmpty(methods)) {
                if (serverMethods == null) {
                    // RFC 4252 section 5.2 says that in the SSH_MSG_USERAUTH_FAILURE response
                    // to a 'none' request a server MAY return a list of methods. Here it didn't,
                    // so we just assume all methods that the client knows are fine.
                    //
                    // https://datatracker.ietf.org/doc/html/rfc4252#section-5.2
                    allowedMethods = new ArrayList<>(clientMethods);
                } else if (partial) {
                    // Don't reset to an empty list; keep going with the previous methods. Sending
                    // a partial success without methods that may continue makes no sense and would
                    // be a server bug.
                    //
                    // currentUserAuth should always be set here!
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "processUserAuth({}) : potential bug in {} server: SSH_MSG_USERAUTH_FAILURE with partial success after {} authentication, but without continuation methods",
                                session, session.getServerVersion(),
                                currentUserAuth != null ? currentUserAuth.getName() : "UNKNOWN");
                    }
                    allowedMethods = serverMethods;
                } else {
                    allowedMethods = new ArrayList<>();
                }
            } else {
                allowedMethods = Arrays.asList(GenericUtils.split(methods, ','));
            }
            if (currentUserAuth != null) {
                try {
                    currentUserAuth.signalAuthMethodFailure(session, service, partial,
                            Collections.unmodifiableList(allowedMethods), buffer);
                } catch (Exception e) {
                    clearUserAuth();
                    throw e;
                }

                // Check if the current method is still allowed.
                if (allowedMethods.indexOf(currentUserAuth.getName()) < 0) {
                    if (currentUserAuth == pubkeyAuth) {
                        // Don't destroy it yet, we might still need it later on
                        currentUserAuth = null;
                    } else {
                        destroyUserAuth();
                    }
                }
            }
            if (partial || (serverMethods == null)) {
                currentMethod = 0;
            }
            serverMethods = allowedMethods;

            tryNext(cmd, authFuture);
            return;
        }

        if (currentUserAuth == null) {
            throw new IllegalStateException("Received unknown packet: " + SshConstants.getCommandMessageName(cmd));
        }

        if (log.isDebugEnabled()) {
            log.debug("processUserAuth({}) delegate processing of {} to {}",
                    session, SshConstants.getCommandMessageName(cmd), currentUserAuth.getName());
        }

        buffer.rpos(buffer.rpos() - 1);
        if (!currentUserAuth.process(buffer)) {
            tryNext(cmd, authFuture);
        } else {
            authFuture.setCancellable(currentUserAuth.isCancellable());
        }
    }

    protected void tryNext(int cmd, AuthFuture authFuture) throws Exception {
        ClientSession session = getClientSession();
        // Loop until we find something to try
        for (boolean debugEnabled = log.isDebugEnabled();; debugEnabled = log.isDebugEnabled()) {
            if (currentUserAuth == null) {
                if (debugEnabled) {
                    log.debug("tryNext({}) starting authentication mechanisms: client={}, client index={}, server={}", session,
                            clientMethods, currentMethod, serverMethods);
                }
            } else if (!currentUserAuth.process(null)) {
                if (debugEnabled) {
                    log.debug("tryNext({}) no initial request sent by method={}", session, currentUserAuth.getName());
                }
                if (currentUserAuth == pubkeyAuth) {
                    // Don't destroy it yet. It might re-appear later if the server requires multiple methods.
                    // It doesn't have any more keys, but we don't want to re-create it from scratch and re-try
                    // all the keys already tried again.
                    currentUserAuth = null;
                } else {
                    destroyUserAuth();
                }
                currentMethod++;
            } else {
                if (debugEnabled) {
                    log.debug("tryNext({}) successfully processed initial buffer by method={}",
                            session, currentUserAuth.getName());
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
                clearUserAuth();
                // also wake up anyone sitting in waitFor
                authFuture.setException(new SshException(SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                        "No more authentication methods available"));
                return;
            }

            authFuture.setCancellable(false);
            if (authFuture.isCanceled()) {
                authFuture.getCancellation().setCanceled();
                clearUserAuth();
                return;
            }
            if (UserAuthPublicKey.NAME.equals(method) && pubkeyAuth != null) {
                currentUserAuth = pubkeyAuth;
            } else {
                currentUserAuth = UserAuthMethodFactory.createUserAuth(session, authFactories, method);
                if (currentUserAuth == null) {
                    throw new UnsupportedOperationException("Failed to find a user-auth factory for method=" + method);
                }
            }
            if (debugEnabled) {
                log.debug("tryNext({}) attempting method={}", session, method);
            }
            if (currentUserAuth != pubkeyAuth) {
                currentUserAuth.init(session, service);
            }
            if (UserAuthPublicKey.NAME.equals(currentUserAuth.getName())) {
                pubkeyAuth = currentUserAuth;
            }
            authFuture.setCancellable(currentUserAuth.isCancellable());
            if (authFuture.isCanceled()) {
                authFuture.getCancellation().setCanceled();
                clearUserAuth();
                return;
            }
        }
    }

    private void clearUserAuth() {
        if (currentUserAuth == pubkeyAuth) {
            pubkeyAuth = null;
            destroyUserAuth();
        } else {
            destroyUserAuth();
            destroyPubkeyAuth();
        }
    }

    private void destroyUserAuth() {
        if (currentUserAuth != null) {
            try {
                currentUserAuth.destroy();
            } finally {
                currentUserAuth = null;
            }
        }
    }

    private void destroyPubkeyAuth() {
        if (pubkeyAuth != null) {
            try {
                pubkeyAuth.destroy();
            } finally {
                pubkeyAuth = null;
            }
        }
    }

    @Override
    protected void preClose() {
        AuthFuture authFuture = authFutureHolder.get();
        if (authFuture != null) {
            authFuture.setException(new SshException("Session is closed"));
        }

        super.preClose();
    }
}
