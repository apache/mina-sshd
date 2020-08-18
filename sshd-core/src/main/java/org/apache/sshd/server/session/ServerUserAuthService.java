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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyRandomArt;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.UserAuthFactory;
import org.apache.sshd.server.auth.UserAuthNoneFactory;
import org.apache.sshd.server.auth.WelcomeBannerPhase;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerUserAuthService extends AbstractCloseable implements Service, ServerSessionHolder {
    private final AtomicBoolean welcomeSent = new AtomicBoolean(false);
    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    private final ServerSession serverSession;
    private final WelcomeBannerPhase welcomePhase;
    private List<UserAuthFactory> userAuthFactories;
    private List<List<String>> authMethods;
    private String authUserName;
    private String authMethod;
    private String authService;
    private UserAuth currentAuth;

    private int maxAuthRequests;
    private int nbAuthRequests;

    public ServerUserAuthService(Session s) throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        serverSession = ValidateUtils.checkInstanceOf(
                s, ServerSession.class, "Server side service used on client side: %s", s);
        if (s.isAuthenticated()) {
            throw new SshException("Session already authenticated");
        }

        welcomePhase = CoreModuleProperties.WELCOME_BANNER_PHASE.getRequired(this);
        maxAuthRequests = CoreModuleProperties.MAX_AUTH_REQUESTS.getRequired(this);

        List<UserAuthFactory> factories = ValidateUtils.checkNotNullAndNotEmpty(
                serverSession.getUserAuthFactories(), "No user auth factories for %s", s);
        userAuthFactories = new ArrayList<>(factories);
        // Get authentication methods
        authMethods = new ArrayList<>();

        String mths = CoreModuleProperties.AUTH_METHODS.getOrNull(this);
        if (GenericUtils.isEmpty(mths)) {
            for (UserAuthFactory uaf : factories) {
                authMethods.add(new ArrayList<>(Collections.singletonList(uaf.getName())));
            }
        } else {
            if (debugEnabled) {
                log.debug("ServerUserAuthService({}) using configured methods={}", s, mths);
            }
            for (String mthl : mths.split("\\s")) {
                authMethods.add(new ArrayList<>(Arrays.asList(GenericUtils.split(mthl, ','))));
            }
        }
        // Verify all required methods are supported
        for (List<String> l : authMethods) {
            for (String m : l) {
                UserAuthFactory factory = NamedResource.findByName(m, String.CASE_INSENSITIVE_ORDER, userAuthFactories);
                if (factory == null) {
                    throw new SshException("Configured method is not supported: " + m);
                }
            }
        }

        if (debugEnabled) {
            log.debug("ServerUserAuthService({}) authorized authentication methods: {}",
                    s, NamedResource.getNames(userAuthFactories));
        }

        s.resetAuthTimeout();
    }

    public WelcomeBannerPhase getWelcomePhase() {
        return welcomePhase;
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
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    public synchronized void process(int cmd, Buffer buffer) throws Exception {
        Boolean authed = Boolean.FALSE;
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();

        if (cmd == SshConstants.SSH_MSG_USERAUTH_REQUEST) {
            AtomicReference<Boolean> authHolder = new AtomicReference<>(authed);
            if (!handleUserAuthRequestMessage(session, buffer, authHolder)) {
                return;
            }

            authed = authHolder.get();
        } else {
            if (WelcomeBannerPhase.FIRST_AUTHCMD.equals(getWelcomePhase())) {
                sendWelcomeBanner(session);
            }

            if (this.currentAuth == null) {
                // This should not happen
                throw new IllegalStateException(
                        "No current authentication mechanism for cmd=" + SshConstants.getCommandMessageName(cmd));
            }

            if (debugEnabled) {
                log.debug("process({}) Received authentication message={} for mechanism={}",
                        session, SshConstants.getCommandMessageName(cmd), currentAuth.getName());
            }

            buffer.rpos(buffer.rpos() - 1);
            try {
                authed = currentAuth.next(buffer);
            } catch (AsyncAuthException async) {
                async.addListener(authenticated -> asyncAuth(cmd, buffer, authenticated));
                return;
            } catch (Exception e) {
                // Continue
                warn("process({}) Failed ({}) to authenticate using current method={}: {}",
                        session, e.getClass().getSimpleName(), currentAuth.getName(), e.getMessage(), e);
            }
        }

        if (authed == null) {
            handleAuthenticationInProgress(cmd, buffer);
        } else if (authed) {
            handleAuthenticationSuccess(cmd, buffer);
        } else {
            handleAuthenticationFailure(cmd, buffer);
        }
    }

    protected boolean handleUserAuthRequestMessage(
            ServerSession session, Buffer buffer, AtomicReference<Boolean> authHolder)
            throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        /*
         * According to RFC4252 section 5.1:
         *
         *
         * When SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication requests received after that SHOULD
         * be silently ignored.
         */
        if (session.isAuthenticated()) {
            String username = buffer.getString();
            String service = buffer.getString();
            String method = buffer.getString();

            if (debugEnabled) {
                log.debug("handleUserAuthRequestMessage({}) ignore user={}, service={}, method={}"
                          + " auth. request since session already authenticated",
                        session, username, service, method);
            }
            return false;
        }

        if (WelcomeBannerPhase.FIRST_REQUEST.equals(getWelcomePhase())) {
            sendWelcomeBanner(session);
        }

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
        if (debugEnabled) {
            log.debug("handleUserAuthRequestMessage({}) Received SSH_MSG_USERAUTH_REQUEST user={}, service={}, method={}",
                    session, username, service, method);
        }

        if ((this.authUserName == null) || (this.authService == null)) {
            this.authUserName = username;
            this.authService = service;
        } else if (this.authUserName.equals(username) && this.authService.equals(service)) {
            nbAuthRequests++;
            if (nbAuthRequests > maxAuthRequests) {
                boolean disconnectSession = true;
                try {
                    SessionDisconnectHandler handler = session.getSessionDisconnectHandler();
                    disconnectSession = (handler == null)
                            || (!handler.handleAuthCountDisconnectReason(
                                    session, this, service, method, username, nbAuthRequests, maxAuthRequests));
                } catch (IOException | RuntimeException e) {
                    warn("handleUserAuthRequestMessage({}) failed ({}) to invoke disconnect handler due to"
                         + " user={}/{}, service={}/{} - {}/{} auth requests: {}",
                            session, e.getClass().getSimpleName(),
                            this.authUserName, username, this.authService, service,
                            nbAuthRequests, maxAuthRequests, e.getMessage(), e);
                }

                if (disconnectSession) {
                    session.disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                            "Too many authentication failures: " + nbAuthRequests);
                    return false;
                }

                if (debugEnabled) {
                    log.debug(
                            "handleUserAuthRequestMessage({}) ignore mismatched authentication counts: user={}/{}, service={}/{}: {}/{}",
                            session, this.authUserName, username, this.authService, service, nbAuthRequests, maxAuthRequests);
                }
            }
        } else {
            boolean disconnectSession = true;
            try {
                SessionDisconnectHandler handler = session.getSessionDisconnectHandler();
                disconnectSession = (handler == null)
                        || (!handler.handleAuthParamsDisconnectReason(
                                session, this, this.authUserName, username, this.authService, service));
            } catch (IOException | RuntimeException e) {
                warn("handleUserAuthRequestMessage({}) failed ({}) to invoke disconnect handler due to"
                     + " user={}/{}, service={}/{} mismatched parameters: {}",
                        session, e.getClass().getSimpleName(),
                        this.authUserName, username, this.authService, service, e.getMessage(), e);
            }

            if (disconnectSession) {
                session.disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                        "Change of username or service is not allowed (" + this.authUserName + ", " + this.authService + ")"
                                                                                + " -> (" + username + ", " + service + ")");
            } else {
                if (debugEnabled) {
                    log.debug(
                            "handleUserAuthRequestMessage({}) ignore mismatched authentication parameters: user={}/{}, service={}/{}",
                            session, this.authUserName, username, this.authService, service);
                }
            }
            return false;
        }

        // TODO: verify that the service is supported
        this.authMethod = method;
        if (debugEnabled) {
            log.debug(
                    "handleUserAuthRequestMessage({}) Authenticating user '{}' with service '{}' and method '{}' (attempt {} / {})",
                    session, username, service, method, nbAuthRequests, maxAuthRequests);
        }

        UserAuthFactory factory = NamedResource.findByName(
                method, String.CASE_INSENSITIVE_ORDER, userAuthFactories);
        if (factory == null) {
            if (debugEnabled) {
                log.debug("handleUserAuthRequestMessage({}) no authentication factory for method={}", session, method);
            }

            return true;
        }

        currentAuth = ValidateUtils.checkNotNull(
                factory.createUserAuth(session), "No authenticator created for method=%s", method);
        try {
            Boolean authed = currentAuth.auth(session, username, service, buffer);
            authHolder.set(authed);
        } catch (AsyncAuthException async) {
            async.addListener(authenticated -> asyncAuth(SshConstants.SSH_MSG_USERAUTH_REQUEST, buffer, authenticated));
            return false;
        } catch (Exception e) {
            warn("handleUserAuthRequestMessage({}) Failed ({}) to authenticate using factory method={}: {}",
                    session, e.getClass().getSimpleName(), method, e.getMessage(), e);
        }

        return true;
    }

    protected synchronized void asyncAuth(int cmd, Buffer buffer, boolean authed) {
        try {
            if (authed) {
                handleAuthenticationSuccess(cmd, buffer);
            } else {
                handleAuthenticationFailure(cmd, buffer);
            }
        } catch (Exception e) {
            ServerSession session = getServerSession();
            warn("asyncAuth({}) Error ({}) performing async authentication via cmd={}: {}",
                    session, e.getClass().getSimpleName(), cmd, e.getMessage(), e);
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
        String username = Objects.requireNonNull(currentAuth, "No current auth").getUsername();
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
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
            Integer maxSessionCount = CoreModuleProperties.MAX_CONCURRENT_SESSIONS.getOrNull(session);
            if (maxSessionCount != null) {
                int currentSessionCount = session.getActiveSessionCountForUser(username);
                if (currentSessionCount >= maxSessionCount) {
                    boolean disconnectSession = true;
                    try {
                        SessionDisconnectHandler handler = session.getSessionDisconnectHandler();
                        disconnectSession = (handler == null)
                                || (!handler.handleSessionsCountDisconnectReason(
                                        session, this, username, currentSessionCount, maxSessionCount));
                    } catch (IOException | RuntimeException e) {
                        warn(
                                "handleAuthenticationSuccess({}@{}) failed ({}) to invoke disconnect handler due to {}/{} sessions count: {}",
                                username, session, e.getClass().getSimpleName(), currentSessionCount, maxSessionCount,
                                e.getMessage(), e);
                    }

                    if (disconnectSession) {
                        session.disconnect(SshConstants.SSH2_DISCONNECT_TOO_MANY_CONNECTIONS,
                                "Too many concurrent connections (" + currentSessionCount + ") - max. allowed: "
                                                                                              + maxSessionCount);
                        return;
                    }

                    if (debugEnabled) {
                        log.debug("handleAuthenticationSuccess({}@{}) ignore {}/{} sessions count due to handler intervention",
                                username, session, currentSessionCount, maxSessionCount);
                    }
                }
            }

            if (WelcomeBannerPhase.POST_SUCCESS.equals(getWelcomePhase())) {
                sendWelcomeBanner(session);
            }

            session.signalAuthenticationSuccess(username, authService, buffer);
        } else {
            String remaining = authMethods.stream()
                    .filter(GenericUtils::isNotEmpty)
                    .map(l -> l.get(0))
                    .collect(Collectors.joining(","));

            if (debugEnabled) {
                log.debug("handleAuthenticationSuccess({}@{}) remaining methods={}", username, session, remaining);
            }

            Buffer response = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE, remaining.length() + Byte.SIZE);
            response.putString(remaining);
            response.putBoolean(true); // partial success ...
            session.writePacket(response);
        }

        try {
            currentAuth.destroy();
        } finally {
            currentAuth = null;
        }
    }

    protected void handleAuthenticationFailure(int cmd, Buffer buffer) throws Exception {
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (WelcomeBannerPhase.FIRST_FAILURE.equals(getWelcomePhase())) {
            sendWelcomeBanner(session);
        }

        String username = (currentAuth == null) ? null : currentAuth.getUsername();
        if (debugEnabled) {
            log.debug("handleAuthenticationFailure({}@{}) {}",
                    username, session, SshConstants.getCommandMessageName(cmd));
        }

        StringBuilder sb = new StringBuilder((authMethods.size() + 1) * Byte.SIZE);
        for (List<String> l : authMethods) {
            if (GenericUtils.size(l) > 0) {
                String m = l.get(0);
                if (!UserAuthNoneFactory.NAME.equals(m)) {
                    if (sb.length() > 0) {
                        sb.append(',');
                    }
                    sb.append(m);
                }
            }
        }

        String remaining = sb.toString();
        if (debugEnabled) {
            log.debug("handleAuthenticationFailure({}@{}) remaining methods: {}", username, session, remaining);
        }

        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE, remaining.length() + Byte.SIZE);
        buffer.putString(remaining);
        buffer.putBoolean(false); // no partial success ...
        session.writePacket(buffer);

        if (currentAuth != null) {
            try {
                currentAuth.destroy();
            } finally {
                currentAuth = null;
            }
        }
    }

    /**
     * Sends the welcome banner (if any configured) and if not already invoked
     *
     * @param  session     The {@link ServerSession} to send the welcome banner to
     * @return             The sent welcome banner {@link IoWriteFuture} - {@code null} if none sent
     * @throws IOException If failed to send the banner
     */
    public IoWriteFuture sendWelcomeBanner(ServerSession session) throws IOException {
        if (welcomeSent.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("sendWelcomeBanner({}) already sent", session);
            }
            return null;
        }

        String welcomeBanner = resolveWelcomeBanner(session);
        if (GenericUtils.isEmpty(welcomeBanner)) {
            return null;
        }

        String lang = CoreModuleProperties.WELCOME_BANNER_LANGUAGE.getRequired(this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_BANNER,
                welcomeBanner.length() + GenericUtils.length(lang) + Long.SIZE);
        buffer.putString(welcomeBanner);
        buffer.putString(lang);

        if (log.isDebugEnabled()) {
            log.debug("sendWelcomeBanner({}) send banner (length={}, lang={})",
                    session, welcomeBanner.length(), lang);
        }
        return session.writePacket(buffer);
    }

    protected String resolveWelcomeBanner(ServerSession session) throws IOException {
        Object bannerValue = CoreModuleProperties.WELCOME_BANNER.getOrNull(this);
        if (bannerValue == null) {
            return null;
        }

        if (bannerValue instanceof CharSequence) {
            String message = bannerValue.toString();
            if (GenericUtils.isEmpty(message)) {
                return null;
            }

            if (CoreModuleProperties.AUTO_WELCOME_BANNER_VALUE.equalsIgnoreCase(message)) {
                try {
                    return KeyRandomArt.combine(session, ' ', session.getKeyPairProvider());
                } catch (Exception e) {
                    if (e instanceof IOException) {
                        throw (IOException) e;
                    }

                    throw new IOException(e);
                }
            }

            if (!message.contains("://")) {
                return message;
            }

            try {
                bannerValue = new URI(message);
            } catch (URISyntaxException e) {
                log.error("resolveWelcomeBanner({}) bad path URI {}: {}", session, message, e.getMessage());
                throw new MalformedURLException(
                        e.getClass().getSimpleName() + " - bad URI (" + message + "): " + e.getMessage());
            }

            if (message.startsWith("file:/")) {
                bannerValue = Paths.get((URI) bannerValue);
            }
        }

        if (bannerValue instanceof File) {
            bannerValue = ((File) bannerValue).toPath();
        }

        if (bannerValue instanceof Path) {
            Path path = (Path) bannerValue;
            if ((!Files.exists(path)) || (Files.size(path) <= 0L)) {
                if (log.isDebugEnabled()) {
                    log.debug("resolveWelcomeBanner({}) file is empty/does not exist {}", session, path);
                }
                return null;
            }
            bannerValue = path.toUri();
        }

        if (bannerValue instanceof URI) {
            bannerValue = ((URI) bannerValue).toURL();
        }

        if (bannerValue instanceof URL) {
            Charset cs = CoreModuleProperties.WELCOME_BANNER_CHARSET.getRequired(this);
            return loadWelcomeBanner(session, (URL) bannerValue, cs);
        }

        return bannerValue.toString();
    }

    protected String loadWelcomeBanner(ServerSession session, URL url, Charset cs) throws IOException {
        try (InputStream stream = url.openStream()) {
            byte[] bytes = IoUtils.toByteArray(stream);
            return NumberUtils.isEmpty(bytes) ? "" : new String(bytes, cs);
        }
    }

    public ServerFactoryManager getFactoryManager() {
        return serverSession.getFactoryManager();
    }
}
