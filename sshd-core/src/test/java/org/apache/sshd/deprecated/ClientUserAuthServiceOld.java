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

package org.apache.sshd.deprecated;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.deprecated.UserAuth.Result;

/**
 * Client side <code>ssh-auth</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
// CHECKSTYLE:OFF
public class ClientUserAuthServiceOld extends AbstractCloseable implements Service {

    public static class Factory implements ServiceFactory {

        @Override
        public String getName() {
            return "ssh-userauth";
        }

        @Override
        public Service create(Session session) throws IOException {
            return new ClientUserAuthServiceOld(session);
        }
    }

    private final Map<String, Object> properties = new ConcurrentHashMap<>();

    /**
     * When !authFuture.isDone() the current authentication
     */
    private UserAuth userAuth;

    /**
     * The AuthFuture that is being used by the current auth request. This encodes the state.
     * isSuccess -> authenticated, else if isDone -> server waiting for user auth, else authenticating.
     */
    private volatile AuthFuture authFuture;

    protected final ClientSessionImpl session;
    protected final Object lock;

    public ClientUserAuthServiceOld(Session s) {
        if (!(s instanceof ClientSessionImpl)) {
            throw new IllegalStateException("Client side service used on server side");
        }
        session = (ClientSessionImpl) s;
        lock = session.getFutureLock();
        // Maintain the current auth status in the authFuture.
        authFuture = new DefaultAuthFuture(s.toString(), lock);
    }

    @Override
    public ClientSessionImpl getSession() {
        return session;
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    public void start() {
        synchronized (lock) {
            log.debug("accepted");
            // kick start the authentication process by failing the pending auth.
            this.authFuture.setAuthed(false);
        }
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
            log.debug("Welcome banner[{}]: {}", lang, welcome);
            UserInteraction ui = session.getUserInteraction();
            if ((ui != null) && ui.isInteractionAllowed(session)) {
                ui.welcome(session, welcome, lang);
            }
        } else {
            buffer.rpos(buffer.rpos() - 1);
            processUserAuth(buffer);
        }
    }

    /*
     * return true if/when ready for auth; false if never ready.
     *
     * @return server is ready and waiting for auth
     */
    private boolean readyForAuth(UserAuth userAuth) {
        // isDone indicates that the last auth finished and a new one can commence.
        while (!this.authFuture.isDone()) {
            log.debug("waiting to send authentication");
            try {
                this.authFuture.await();    // TODO use verify + configurable timeout
            } catch (IOException e) {
                log.debug("Unexpected exception", e);
                throw new RuntimeException(e);
            }
        }
        if (this.authFuture.isSuccess()) {
            log.debug("already authenticated");
            throw new IllegalStateException("Already authenticated");
        }

        Throwable err = this.authFuture.getException();
        if (err != null) {
            log.debug("probably closed", err);
            return false;
        }
        if (!this.authFuture.isFailure()) {
            log.debug("unexpected state");
            throw new IllegalStateException("Unexpected authentication state");
        }
        if (this.userAuth != null) {
            log.debug("authentication already in progress");
            throw new IllegalStateException("Authentication already in progress?");
        }
        // Set up the next round of authentication. Each round gets a new lock.
        this.userAuth = userAuth;
        // The new future !isDone() - i.e., in progress blocking out other waits.
        this.authFuture = new DefaultAuthFuture(getClass().getSimpleName(), lock);
        log.debug("ready to try authentication with new lock");
        return true;
    }

    /**
     * execute one step in user authentication.
     *
     * @param buffer
     * @throws java.io.IOException
     */
    private void processUserAuth(Buffer buffer) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("processing {}", userAuth);
        }
        Result result = userAuth.next(buffer);
        switch (result) {
            case Success:
                if (log.isDebugEnabled()) {
                    log.debug("succeeded with {}", userAuth);
                }
                session.setAuthenticated();
                session.switchToNextService();
                // Will wake up anyone sitting in waitFor
                authFuture.setAuthed(true);
                break;
            case Failure:
                if (log.isDebugEnabled()) {
                    log.debug("failed with {}", userAuth);
                }
                this.userAuth = null;
                // Will wake up anyone sitting in waitFor
                this.authFuture.setAuthed(false);
                break;
            case Continued:
                // Will wake up anyone sitting in waitFor
                if (log.isDebugEnabled()) {
                    log.debug("continuing with {}", userAuth);
                }
                break;
            default:
                if (log.isDebugEnabled()) {
                    log.debug("ignored result={} for {}", result, userAuth);
                }
        }
    }

    @Override
    protected void preClose() {
        if (!authFuture.isDone()) {
            authFuture.setException(new SshException("Session is closed"));
        }
        super.preClose();
    }

    public AuthFuture auth(UserAuth userAuth) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Trying authentication with {}", userAuth);
        }

        synchronized (lock) {
            if (readyForAuth(userAuth)) {
                processUserAuth(null);
            }
            return authFuture;
        }
    }

}
// CHECKSTYLE:ON
