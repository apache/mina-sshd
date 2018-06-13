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

package org.apache.sshd.client.subsystem.sftp.impl;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.SocketAddress;
import java.security.KeyPair;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClientFactory;
import org.apache.sshd.client.subsystem.sftp.SimpleSftpClient;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

public class SimpleSftpClientImpl extends AbstractLoggingBean implements SimpleSftpClient {

    private SimpleClient clientInstance;
    private SftpClientFactory sftpClientFactory;

    public SimpleSftpClientImpl() {
        this(null);
    }

    public SimpleSftpClientImpl(SimpleClient client) {
        this(client, null);
    }

    public SimpleSftpClientImpl(SimpleClient client, SftpClientFactory sftpClientFactory) {
        this.clientInstance = client;
        setSftpClientFactory(sftpClientFactory);
    }

    public SimpleClient getClient() {
        return clientInstance;
    }

    public void setClient(SimpleClient client) {
        this.clientInstance = client;
    }

    public SftpClientFactory getSftpClientFactory() {
        return sftpClientFactory;
    }

    public void setSftpClientFactory(SftpClientFactory sftpClientFactory) {
        this.sftpClientFactory = (sftpClientFactory != null) ? sftpClientFactory : SftpClientFactory.instance();
    }

    @Override
    public SftpClient sftpLogin(SocketAddress target, String username, String password) throws IOException {
        return createSftpClient(client -> client.sessionLogin(target, username, password));
    }

    @Override
    public SftpClient sftpLogin(SocketAddress target, String username, KeyPair identity) throws IOException {
        return createSftpClient(client -> client.sessionLogin(target, username, identity));
    }

    protected SftpClient createSftpClient(IOFunction<? super SimpleClient, ? extends ClientSession> sessionProvider) throws IOException {
        SimpleClient client = getClient();
        ClientSession session = sessionProvider.apply(client);
        try {
            SftpClient sftp = createSftpClient(session);
            session = null; // disable auto-close at finally block
            return sftp;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    protected SftpClient createSftpClient(ClientSession session) throws IOException {
        Exception err = null;
        try {
            SftpClient client = sftpClientFactory.createSftpClient(session);
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

    protected SftpClient createSftpClient(ClientSession session, SftpClient client) throws IOException {
        ClassLoader loader = getClass().getClassLoader();
        Class<?>[] interfaces = {SftpClient.class};
        return (SftpClient) Proxy.newProxyInstance(loader, interfaces, (proxy, method, args) -> {
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
