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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyPair;

import org.apache.sshd.client.scp.CloseableScpClient;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
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
    public SftpClient sftpLogin(String host, String username, String password) throws IOException {
        return sftpLogin(host, DEFAULT_PORT, username, password);
    }

    @Override
    public SftpClient sftpLogin(String host, int port, String username, String password) throws IOException {
        return sftpLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username, password);
    }

    @Override
    public SftpClient sftpLogin(String host, String username, KeyPair identity) throws IOException {
        return sftpLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override
    public SftpClient sftpLogin(String host, int port, String username, KeyPair identity) throws IOException {
        return sftpLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username, identity);
    }

    @Override
    public SftpClient sftpLogin(InetAddress host, String username, String password) throws IOException {
        return sftpLogin(host, DEFAULT_PORT, username, password);
    }

    @Override
    public SftpClient sftpLogin(InetAddress host, int port, String username, String password) throws IOException {
        return sftpLogin(new InetSocketAddress(ValidateUtils.checkNotNull(host, "No host address"), port), username, password);
    }

    @Override
    public SftpClient sftpLogin(InetAddress host, String username, KeyPair identity) throws IOException {
        return sftpLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override
    public SftpClient sftpLogin(InetAddress host, int port, String username, KeyPair identity) throws IOException {
        return sftpLogin(new InetSocketAddress(ValidateUtils.checkNotNull(host, "No host address"), port), username, identity);
    }

    @Override
    public SftpClient sftpLogin(SocketAddress target, String username, String password) throws IOException {
        return createSftpClient(sessionLogin(target, username, password));
    }

    @Override
    public SftpClient sftpLogin(SocketAddress target, String username, KeyPair identity) throws IOException {
        return createSftpClient(sessionLogin(target, username, identity));
    }

    protected SftpClient createSftpClient(final ClientSession session) throws IOException {
        Exception err = null;
        try {
            final SftpClient client = session.createSftpClient();
            try {
                return createSftpClient(session, client);
            } catch (Exception e) {
                err = GenericUtils.accumulateException(err, e);
                try {
                    client.close();
                } catch (Exception t) {
                    if (log.isDebugEnabled()) {
                        log.debug("createSftpClient({}) failed ({}) to close client: {}",
                                  session, t.getClass().getSimpleName(), t.getMessage());
                    }

                    if (log.isTraceEnabled()) {
                        log.trace("createSftpClient(" + session + ") client close failure details", t);
                    }
                    err = GenericUtils.accumulateException(err, t);
                }
            }
        } catch (Exception e) {
            err = GenericUtils.accumulateException(err, e);
        }

        // This point is reached if error occurred
        log.warn("createSftpClient({}) failed ({}) to create session: {}",
                 session, err.getClass().getSimpleName(), err.getMessage());

        try {
            session.close();
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("createSftpClient({}) failed ({}) to close session: {}",
                          session, e.getClass().getSimpleName(), e.getMessage());
            }

            if (log.isTraceEnabled()) {
                log.trace("createSftpClient(" + session + ") session close failure details", e);
            }
            err = GenericUtils.accumulateException(err, e);
        }

        if (err instanceof IOException) {
            throw (IOException) err;
        } else {
            throw new IOException(err);
        }
    }

    protected SftpClient createSftpClient(final ClientSession session, final SftpClient client) throws IOException {
        ClassLoader loader = getClass().getClassLoader();
        Class<?>[] interfaces = {SftpClient.class};
        return (SftpClient) Proxy.newProxyInstance(loader, interfaces, new InvocationHandler() {
            @SuppressWarnings("synthetic-access")
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                Throwable err = null;
                Object result = null;
                String name = method.getName();
                try {
                    result = method.invoke(client, args);
                } catch (Throwable t) {
                    if (log.isTraceEnabled()) {
                        log.trace("invoke(SftpClient#{}) failed ({}) to execute: {}",
                                  name, t.getClass().getSimpleName(), t.getMessage());
                    }
                    err = GenericUtils.accumulateException(err, t);
                }

                // propagate the "close" call to the session as well
                if ("close".equals(name) && GenericUtils.isEmpty(args)) {
                    try {
                        session.close();
                    } catch (Throwable t) {
                        if (log.isDebugEnabled()) {
                            log.debug("invoke(ClientSession#{}) failed ({}) to execute: {}",
                                      name, t.getClass().getSimpleName(), t.getMessage());
                        }
                        err = GenericUtils.accumulateException(err, t);
                    }
                }

                if (err != null) {
                    throw err;
                }

                return result;
            }
        });
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
        return scpLogin(new InetSocketAddress(ValidateUtils.checkNotNull(host, "No host address"), port), username, password);
    }

    @Override
    public CloseableScpClient scpLogin(InetAddress host, String username, KeyPair identity) throws IOException {
        return scpLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override
    public CloseableScpClient scpLogin(InetAddress host, int port, String username, KeyPair identity) throws IOException {
        return scpLogin(new InetSocketAddress(ValidateUtils.checkNotNull(host, "No host address"), port), username, identity);
    }

    @Override
    public CloseableScpClient scpLogin(SocketAddress target, String username, String password) throws IOException {
        return createScpClient(sessionLogin(target, username, password));
    }

    @Override
    public CloseableScpClient scpLogin(SocketAddress target, String username, KeyPair identity) throws IOException {
        return createScpClient(sessionLogin(target, username, identity));
    }

    protected CloseableScpClient createScpClient(final ClientSession session) throws IOException {
        try {
            final ScpClient client = ValidateUtils.checkNotNull(session, "No client session").createScpClient();
            ClassLoader loader = getClass().getClassLoader();
            Class<?>[] interfaces = {CloseableScpClient.class};
            return (CloseableScpClient) Proxy.newProxyInstance(loader, interfaces, new InvocationHandler() {
                @SuppressWarnings("synthetic-access")
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
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

            if (e instanceof IOException) {
                throw (IOException) e;
            } else {
                throw new IOException(e);
            }
        }
    }

    @Override   // TODO make this a default method in Java-8
    public ClientSession sessionLogin(String host, String username, String password) throws IOException {
        return sessionLogin(host, DEFAULT_PORT, username, password);
    }

    @Override   // TODO make this a default method in Java-8
    public ClientSession sessionLogin(String host, String username, KeyPair identity) throws IOException {
        return sessionLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override   // TODO make this a default method in Java-8
    public ClientSession sessionLogin(InetAddress host, String username, String password) throws IOException {
        return sessionLogin(host, DEFAULT_PORT, username, password);
    }

    @Override
    public ClientSession sessionLogin(InetAddress host, String username, KeyPair identity) throws IOException {
        return sessionLogin(host, DEFAULT_PORT, username, identity);
    }

    @Override   // TODO make this a default method in Java-8
    public ClientSession sessionLogin(String host, int port, String username, String password) throws IOException {
        return sessionLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username, password);
    }

    @Override   // TODO make this a default method in Java-8
    public ClientSession sessionLogin(InetAddress host, int port, String username, String password) throws IOException {
        return sessionLogin(new InetSocketAddress(ValidateUtils.checkNotNull(host, "No host address"), port), username, password);
    }

    @Override   // TODO make this a default method in Java-8
    public ClientSession sessionLogin(String host, int port, String username, KeyPair identity) throws IOException {
        return sessionLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username, identity);
    }

    @Override
    public ClientSession sessionLogin(InetAddress host, int port, String username, KeyPair identity) throws IOException {
        return sessionLogin(new InetSocketAddress(ValidateUtils.checkNotNull(host, "No host address"), port), username, identity);
    }
}
