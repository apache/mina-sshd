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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.UserAuth;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerUserAuthService extends CloseableUtils.AbstractCloseable implements Service {

    public static class Factory implements ServiceFactory {

        public String getName() {
            return "ssh-userauth";
        }

        public Service create(Session session) throws IOException {
            return new ServerUserAuthService(session);
        }
    }

    private final ServerSession session;
    private List<NamedFactory<UserAuth>> userAuthFactories;
    private List<List<String>> authMethods;
    private String authUserName;
    private String authMethod;
    private String authService;
    private UserAuth currentAuth;

    private int maxAuthRequests = 20;
    private int nbAuthRequests;

    public ServerUserAuthService(Session s) throws SshException {
        if (!(s instanceof ServerSession)) {
            throw new IllegalStateException("Server side service used on client side");
        }
        this.session = (ServerSession) s;
        if (session.isAuthenticated()) {
            throw new SshException("Session already authenticated");
        }
        maxAuthRequests = session.getIntProperty(ServerFactoryManager.MAX_AUTH_REQUESTS, maxAuthRequests);

        userAuthFactories = new ArrayList<>(getFactoryManager().getUserAuthFactories());
        // Get authentication methods
        authMethods = new ArrayList<>();
        
        ServerFactoryManager  manager=getFactoryManager();
        String mths = FactoryManagerUtils.getString(manager, ServerFactoryManager.AUTH_METHODS);
        if (GenericUtils.isEmpty(mths)) {
            for (NamedFactory<UserAuth> uaf : manager.getUserAuthFactories()) {
                authMethods.add(new ArrayList<>(Collections.singletonList(uaf.getName())));
            }
        } else {
            for (String mthl : mths.split("\\s")) {
                authMethods.add(new ArrayList<>(Arrays.asList(mthl.split(","))));
            }
        }
        // Verify all required methods are supported
        for (List<String> l : authMethods) {
            for (String m : l) {
                if (NamedFactory.Utils.get(userAuthFactories, m) == null) {
                    throw new SshException("Configured method is not supported: " + m);
                }
            }
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Authorized authentication methods: {}", NamedResource.Utils.getNames(userAuthFactories));
        }
    }

    public void start() {
        // do nothing
    }

    public ServerSession getSession() {
        return session;
    }

    public void process(byte cmd, Buffer buffer) throws Exception {
        Boolean authed = Boolean.FALSE;

        if (cmd == SshConstants.SSH_MSG_USERAUTH_REQUEST) {
            log.debug("Received SSH_MSG_USERAUTH_REQUEST");
            if (this.currentAuth != null) {
                this.currentAuth.destroy();
                this.currentAuth = null;
            }

            String username = buffer.getString();
            String service = buffer.getString();
            String method = buffer.getString();
            if (this.authUserName == null || this.authService == null) {
                this.authUserName = username;
                this.authService = service;
            } else if (!this.authUserName.equals(username) || !this.authService.equals(service)) {
                session.disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                        "Change of username or service is not allowed (" + this.authUserName + ", " + this.authService + ") -> ("
                                + username + ", " + service + ")");
                return;
            }
            // TODO: verify that the service is supported
            this.authMethod = method;
            if (nbAuthRequests++ > maxAuthRequests) {
                session.disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Too many authentication failures");
                return;
            }

            log.debug("Authenticating user '{}' with service '{}' and method '{}'", new Object[] { username, service, method });
            NamedFactory<UserAuth> factory = NamedFactory.Utils.get(userAuthFactories, method);
            if (factory != null) {
                currentAuth = factory.create();
                try {
                    authed = currentAuth.auth(session, username, service, buffer);
                } catch (Exception e) {
                    // Continue
                    log.debug("Authentication failed: {}", e.getMessage());
                }
            }
        } else  {
            if (this.currentAuth == null) {
                // This should not happen
                throw new IllegalStateException();
            }
            log.debug("Received authentication message {}", cmd);
            buffer.rpos(buffer.rpos() - 1);
            try {
                authed = currentAuth.next(buffer);
            } catch (Exception e) {
                // Continue
                log.debug("Authentication failed: {}", e.getMessage());
            }
        }

        if (authed == null) {
            // authentication is still ongoing
            log.debug("Authentication not finished");
        } else if (authed) {
            log.debug("Authentication succeeded");
            String username = currentAuth.getUserName();

            boolean success = false;
            for (List<String> l : authMethods) {
                if (!l.isEmpty() && l.get(0).equals(authMethod)) {
                    l.remove(0);
                    success |= l.isEmpty();
                }
            }

            if (success) {
                FactoryManager manager = getFactoryManager();
                Integer maxSessionCount = FactoryManagerUtils.getInteger(manager, ServerFactoryManager.MAX_CONCURRENT_SESSIONS);
                if (maxSessionCount != null) {
                    int currentSessionCount = session.getActiveSessionCountForUser(username);
                    if (currentSessionCount >= maxSessionCount) {
                        session.disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,
                                "Too many concurrent connections (" + currentSessionCount + ") - max. allowed: " + maxSessionCount);
                        return;
                    }
                }

                String welcomeBanner = FactoryManagerUtils.getString(manager, ServerFactoryManager.WELCOME_BANNER);
                if (welcomeBanner != null) {
                    buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_BANNER);
                    buffer.putString(welcomeBanner);
                    buffer.putString("en");
                    session.writePacket(buffer);
                }

                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_SUCCESS);
                session.writePacket(buffer);
                session.setUsername(username);
                session.setAuthenticated();
                session.startService(authService);
                session.resetIdleTimeout();
                log.info("Session {}@{} authenticated", username, session.getIoSession().getRemoteAddress());

            } else {
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE);
                StringBuilder sb = new StringBuilder();
                for (List<String> l : authMethods) {
                    if (!l.isEmpty()) {
                        if (sb.length() > 0) {
                            sb.append(",");
                        }
                        sb.append(l.get(0));
                    }
                }
                buffer.putString(sb.toString());
                buffer.putByte((byte) 1);
                session.writePacket(buffer);
            }

            currentAuth.destroy();
            currentAuth = null;
        } else {
            log.debug("Authentication failed");

            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE);
            StringBuilder sb = new StringBuilder();
            for (List<String> l : authMethods) {
                if (!l.isEmpty()) {
                    String m = l.get(0);
                    if (!"none".equals(m)) {
                        if (sb.length() > 0) {
                            sb.append(",");
                        }
                        sb.append(l.get(0));
                    }
                }
            }
            buffer.putString(sb.toString());
            buffer.putByte((byte) 0);
            session.writePacket(buffer);

            if (currentAuth != null) {
                currentAuth.destroy();
                currentAuth = null;
            }
        }
    }

    private ServerFactoryManager getFactoryManager() {
        return session.getFactoryManager();
    }

}
