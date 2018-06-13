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

package org.apache.sshd.client.scp;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SimpleScpClientImpl extends AbstractLoggingBean implements SimpleScpClient {
    private SimpleClient clientInstance;
    private ScpClientCreator scpClientCreator;

    public SimpleScpClientImpl() {
        this(null);
    }

    public SimpleScpClientImpl(SimpleClient client) {
        this(client, null);
    }

    public SimpleScpClientImpl(SimpleClient client, ScpClientCreator scpClientCreator) {
        this.clientInstance = client;
        setScpClientCreator(scpClientCreator);
    }

    public SimpleClient getClient() {
        return clientInstance;
    }

    public void setClient(SimpleClient client) {
        this.clientInstance = client;
    }

    public ScpClientCreator getScpClientCreator() {
        return scpClientCreator;
    }

    public void setScpClientCreator(ScpClientCreator scpClientCreator) {
        this.scpClientCreator = (scpClientCreator == null) ? ScpClientCreator.instance() : scpClientCreator;
    }

    @Override
    public CloseableScpClient scpLogin(SocketAddress target, String username, String password) throws IOException {
        return createScpClient(client -> client.sessionLogin(target, username, password));
    }

    @Override
    public CloseableScpClient scpLogin(SocketAddress target, String username, KeyPair identity) throws IOException {
        return createScpClient(client -> client.sessionLogin(target, username, identity));
    }

    protected CloseableScpClient createScpClient(IOFunction<? super SimpleClient, ? extends ClientSession> sessionProvider) throws IOException {
        SimpleClient client = getClient();
        ClientSession session = sessionProvider.apply(client);
        try {
            CloseableScpClient scp = createScpClient(session);
            session = null; // disable auto-close at finally block
            return scp;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    protected CloseableScpClient createScpClient(ClientSession session) throws IOException {
        try {
            ScpClientCreator creator = getScpClientCreator();
            ScpClient client = creator.createScpClient(Objects.requireNonNull(session, "No client session"));
            return createScpClient(session, client);
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

    protected CloseableScpClient createScpClient(ClientSession session, ScpClient client) throws IOException {
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
    }

    @Override
    public boolean isOpen() {
        return true;
    }

    @Override
    public void close() throws IOException {
        // Do nothing
    }
}
