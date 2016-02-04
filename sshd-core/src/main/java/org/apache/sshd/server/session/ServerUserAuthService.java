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
package org.apache.sshd.server.session;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.UserAuthNoneFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerUserAuthService extends AbstractCloseable implements Service, ServerSessionHolder {

    private final ServerSession serverSession;
    private List<NamedFactory<UserAuth>> userAuthFactories;
    private List<List<String>> authMethods;
    private String authUserName;
    private String authMethod;
    private String authService;
    private UserAuth currentAuth;

    private int maxAuthRequests;
    private int nbAuthRequests;

    public ServerUserAuthService(Session s) throws SshException {
        ValidateUtils.checkTrue(s instanceof ServerSession, "Server side service used on client side");
        if (s.isAuthenticated()) {
            throw new SshException("Session already authenticated");
        }

        serverSession = (ServerSession) s;
        maxAuthRequests = PropertyResolverUtils.getIntProperty(s, ServerAuthenticationManager.MAX_AUTH_REQUESTS, ServerAuthenticationManager.DEFAULT_MAX_AUTH_REQUESTS);

        List<NamedFactory<UserAuth>> factories = ValidateUtils.checkNotNullAndNotEmpty(
                serverSession.getUserAuthFactories(), "No user auth factories for %s", s);
        userAuthFactories = new ArrayList<>(factories);
        // Get authentication methods
        authMethods = new ArrayList<>();

        String mths = PropertyResolverUtils.getString(s, ServerFactoryManager.AUTH_METHODS);
        if (GenericUtils.isEmpty(mths)) {
            for (NamedFactory<UserAuth> uaf : factories) {
                authMethods.add(new ArrayList<>(Collections.singletonList(uaf.getName())));
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("ServerUserAuthService({}) using configured methods={}", s, mths);
            }
            for (String mthl : mths.split("\\s")) {
                authMethods.add(new ArrayList<>(Arrays.asList(GenericUtils.split(mthl, ','))));
            }
        }
        // Verify all required methods are supported
        for (List<String> l : authMethods) {
            for (String m : l) {
                NamedFactory<UserAuth> factory = NamedResource.Utils.findByName(m, String.CASE_INSENSITIVE_ORDER, userAuthFactories);
                if (factory == null) {
                    throw new SshException("Configured method is not supported: " + m);
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("ServerUserAuthService({}) authorized authentication methods: {}",
                      s, NamedResource.Utils.getNames(userAuthFactories));
        }
    }

    @Override
    public void start() {
        // do nothing
    }

    @Override
    public ServerSession getSession() {
        return getServerSession();
    }

    @Override
    public ServerSession getServerSession() {
        return serverSession;
    }

    @Override
    public void process(int cmd, Buffer buffer) throws Exception {
        Boolean authed = Boolean.FALSE;
        ServerSession session = getServerSession();

        if (cmd == SshConstants.SSH_MSG_USERAUTH_REQUEST) {
            if (currentAuth != null) {
                try {
                    currentAuth.destroy();
                } finally {
                    currentAuth = null;
                }
            }

            String username = buffer.getString();
            String service = buffer.getString();
            String method = buffer.getString();
            if (log.isDebugEnabled()) {
                log.debug("process({}) Received SSH_MSG_USERAUTH_REQUEST user={}, service={}, method={}",
                          session, username, service, method);
            }

            if (this.authUserName == null || this.authService == null) {
                this.authUserName = username;
                this.authService = service;
            } else if (this.authUserName.equals(username) && this.authService.equals(service)) {
                if (nbAuthRequests++ > maxAuthRequests) {
                    session.disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Too many authentication failures: " + nbAuthRequests);
                    return;
                }
            } else {
                session.disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                        "Change of username or service is not allowed (" + this.authUserName + ", " + this.authService + ") -> ("
                                + username + ", " + service + ")");
                return;
            }

            // TODO: verify that the service is supported
            this.authMethod = method;
            if (log.isDebugEnabled()) {
                log.debug("process({}) Authenticating user '{}' with service '{}' and method '{}' (attempt {} / {})",
                          session, username, service, method, nbAuthRequests, maxAuthRequests);
            }

            Factory<UserAuth> factory = NamedResource.Utils.findByName(method, String.CASE_INSENSITIVE_ORDER, userAuthFactories);
            if (factory != null) {
                currentAuth = ValidateUtils.checkNotNull(factory.create(), "No authenticator created for method=%s", method);
                try {
                    authed = currentAuth.auth(session, username, service, buffer);
                } catch (Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug("process({}) Failed ({}) to authenticate using factory method={}: {}",
                                  session, e.getClass().getSimpleName(), method, e.getMessage());
                    }
                    if (log.isTraceEnabled()) {
                        log.trace("process(" + session + ") factory authentication=" + method + " failure details", e);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("process({}) no authentication factory for method={}", session, method);
                }
            }
        } else {
            if (this.currentAuth == null) {
                // This should not happen
                throw new IllegalStateException("No current authentication mechanism for cmd=" + SshConstants.getCommandMessageName(cmd));
            }

            if (log.isDebugEnabled()) {
                log.debug("process({}) Received authentication message={} for mechanism={}",
                          session, SshConstants.getCommandMessageName(cmd), currentAuth.getName());
            }

            buffer.rpos(buffer.rpos() - 1);
            try {
                authed = currentAuth.next(buffer);
            } catch (Exception e) {
                // Continue
                if (log.isDebugEnabled()) {
                    log.debug("process({}) Failed ({}) to authenticate using current method={}: {}",
                              session, e.getClass().getSimpleName(), currentAuth.getName(), e.getMessage());
                }
                if (log.isTraceEnabled()) {
                    log.trace("process(" + session + ") current authentiaction=" + currentAuth.getName() + " failure details", e);
                }
            }
        }

        if (authed == null) {
            handleAuthenticationInProgress(cmd, buffer);
        } else if (authed.booleanValue()) {
            handleAuthenticationSuccess(cmd, buffer);
        } else {
            handleAuthenticationFailure(cmd, buffer);
        }
    }

    protected void handleAuthenticationInProgress(int cmd, Buffer buffer) throws Exception {
        String username = (currentAuth == null) ? null : currentAuth.getUsername();
        if (log.isDebugEnabled()) {
            log.debug("handleAuthenticationInProgress({}@{}) {}",
                      username, getServerSession(), SshConstants.getCommandMessageName(cmd));
        }
    }

    protected void handleAuthenticationSuccess(int cmd, Buffer buffer) throws Exception {
        String username = ValidateUtils.checkNotNull(currentAuth, "No current auth").getUsername();
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("handleAuthenticationSuccess({}@{}) {}",
                      username, session, SshConstants.getCommandMessageName(cmd));
        }

        boolean success = false;
        for (List<String> l : authMethods) {
            if ((GenericUtils.size(l) > 0) && l.get(0).equals(authMethod)) {
                l.remove(0);
                success |= l.isEmpty();
            }
        }

        if (success) {
            Integer maxSessionCount = PropertyResolverUtils.getInteger(session, ServerFactoryManager.MAX_CONCURRENT_SESSIONS);
            if (maxSessionCount != null) {
                int currentSessionCount = session.getActiveSessionCountForUser(username);
                if (currentSessionCount >= maxSessionCount) {
                    session.disconnect(SshConstants.SSH2_DISCONNECT_TOO_MANY_CONNECTIONS,
                            "Too many concurrent connections (" + currentSessionCount + ") - max. allowed: " + maxSessionCount);
                    return;
                }
            }

            /*
             * TODO check if we can send the banner sooner. According to RFC-4252 section 5.4:
             *
             *      The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
             *      time after this authentication protocol starts and before
             *      authentication is successful.  This message contains text to be
             *      displayed to the client user before authentication is attempted.
             */
            String welcomeBanner = PropertyResolverUtils.getString(session, ServerFactoryManager.WELCOME_BANNER);
            if (GenericUtils.length(welcomeBanner) > 0) {
                String lang = PropertyResolverUtils.getStringProperty(session,
                                        ServerFactoryManager.WELCOME_BANNER_LANGUAGE,
                                        ServerFactoryManager.DEFAULT_WELCOME_BANNER_LANGUAGE);
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_BANNER,
                        welcomeBanner.length() + GenericUtils.length(lang) + Long.SIZE);
                buffer.putString(welcomeBanner);
                buffer.putString(lang);

                if (log.isDebugEnabled()) {
                    log.debug("handleAuthenticationSuccess({}@{}) send banner (length={}, lang={})",
                              username, session, welcomeBanner.length(), lang);
                }
                session.writePacket(buffer);
            }

            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_SUCCESS, Byte.SIZE);
            session.writePacket(buffer);
            session.setUsername(username);
            session.setAuthenticated();
            session.startService(authService);
            session.resetIdleTimeout();
            log.info("Session {}@{} authenticated", username, session.getIoSession().getRemoteAddress());
        } else {
            StringBuilder sb = new StringBuilder();
            for (List<String> l : authMethods) {
                if (GenericUtils.size(l) > 0) {
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    sb.append(l.get(0));
                }
            }

            String remaining = sb.toString();
            if (log.isDebugEnabled()) {
                log.debug("handleAuthenticationSuccess({}@{}) remaining methods={}", username, session, remaining);
            }

            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE, remaining.length() + Byte.SIZE);
            buffer.putString(remaining);
            buffer.putBoolean(true);    // partial success ...
            session.writePacket(buffer);
        }

        try {
            currentAuth.destroy();
        } finally {
            currentAuth = null;
        }
    }

    protected void handleAuthenticationFailure(int cmd, Buffer buffer) throws Exception {
        String username = (currentAuth == null) ? null : currentAuth.getUsername();
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("handleAuthenticationFailure({}@{}) {}",
                      username, session, SshConstants.getCommandMessageName(cmd));
        }

        StringBuilder sb = new StringBuilder((authMethods.size() + 1) * Byte.SIZE);
        for (List<String> l : authMethods) {
            if (GenericUtils.size(l) > 0) {
                String m = l.get(0);
                if (!UserAuthNoneFactory.NAME.equals(m)) {
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    sb.append(m);
                }
            }
        }

        String remaining = sb.toString();
        if (log.isDebugEnabled()) {
            log.debug("handleAuthenticationFailure({}@{}) remaining methods: {}", username, session, remaining);
        }

        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE, remaining.length() + Byte.SIZE);
        buffer.putString(remaining);
        buffer.putBoolean(false);   // no partial success ...
        session.writePacket(buffer);

        if (currentAuth != null) {
            try {
                currentAuth.destroy();
            } finally {
                currentAuth = null;
            }
        }
    }

    public ServerFactoryManager getFactoryManager() {
        return serverSession.getFactoryManager();
    }
}
