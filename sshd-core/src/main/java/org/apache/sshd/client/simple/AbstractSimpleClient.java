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

package org.apache.sshd.client.simple;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.client.scp.CloseableScpClient;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSimpleClient extends AbstractLoggingBean implements SimpleClient {
    protected AbstractSimpleClient() {
        super();
    }

    @Override
    public CloseableScpClient scpLogin(String host, String username, String password) throws IOException {
        return scpLogin(host, DEFAULT_PORT, username, password);
    }

    @Override
    public CloseableScpClient scpLogin(String host, int port, String username, String password) throws IOException {
        return scpLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username, password);
    }

    @Override
    public CloseableScpClient scpLogin(String host, String username, KeyPair identity) throws IOException {
        return scpLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override
    public CloseableScpClient scpLogin(String host, int port, String username, KeyPair identity) throws IOException {
        return scpLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username, identity);
    }

    @Override
    public CloseableScpClient scpLogin(InetAddress host, String username, String password) throws IOException {
        return scpLogin(host, DEFAULT_PORT, username, password);
    }

    @Override
    public CloseableScpClient scpLogin(InetAddress host, int port, String username, String password) throws IOException {
        return scpLogin(new InetSocketAddress(Objects.requireNonNull(host, "No host address"), port), username, password);
    }

    @Override
    public CloseableScpClient scpLogin(InetAddress host, String username, KeyPair identity) throws IOException {
        return scpLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override
    public CloseableScpClient scpLogin(InetAddress host, int port, String username, KeyPair identity) throws IOException {
        return scpLogin(new InetSocketAddress(Objects.requireNonNull(host, "No host address"), port), username, identity);
    }

    @Override
    public CloseableScpClient scpLogin(SocketAddress target, String username, String password) throws IOException {
        return createScpClient(sessionLogin(target, username, password));
    }

    @Override
    public CloseableScpClient scpLogin(SocketAddress target, String username, KeyPair identity) throws IOException {
        return createScpClient(sessionLogin(target, username, identity));
    }

    protected CloseableScpClient createScpClient(ClientSession session) throws IOException {
        try {
            ScpClient client = Objects.requireNonNull(session, "No client session").createScpClient();
            ClassLoader loader = getClass().getClassLoader();
            Class<?>[] interfaces = {CloseableScpClient.class};
            return (CloseableScpClient) Proxy.newProxyInstance(loader, interfaces, (proxy, method, args) -> {
                String name = method.getName();
                try {
                    // The Channel implementation is provided by the session
                    if (("close".equals(name) || "isOpen".equals(name)) && GenericUtils.isEmpty(args)) {
                        return method.invoke(session, args);
                    } else {
                        return method.invoke(client, args);
                    }
                } catch (Throwable t) {
                    if (log.isTraceEnabled()) {
                        log.trace("invoke(CloseableScpClient#{}) failed ({}) to execute: {}",
                                  name, t.getClass().getSimpleName(), t.getMessage());
                    }
                    throw t;
                }
            });
        } catch (Exception e) {
            log.warn("createScpClient({}) failed ({}) to create proxy: {}",
                     session, e.getClass().getSimpleName(), e.getMessage());
            try {
                session.close();
            } catch (Exception t) {
                if (log.isDebugEnabled()) {
                    log.debug("createScpClient({}) failed ({}) to close session: {}",
                              session, t.getClass().getSimpleName(), t.getMessage());
                }

                if (log.isTraceEnabled()) {
                    log.trace("createScpClient(" + session + ") session close failure details", t);
                }
                e.addSuppressed(t);
            }

            throw GenericUtils.toIOException(e);
        }
    }
}
