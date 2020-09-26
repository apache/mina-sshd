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

package org.apache.sshd.sftp.client.impl;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.KeyPair;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SimpleSftpClient;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
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

    protected SftpClient createSftpClient(IOFunction<? super SimpleClient, ? extends ClientSession> sessionProvider)
            throws IOException {
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
                SftpClient closer = client.singleSessionInstance();
                client = null; // disable auto-close at finally block
                return closer;
            } catch (Exception e) {
                err = GenericUtils.accumulateException(err, e);
            } finally {
                if (client != null) {
                    try {
                        client.close();
                    } catch (Exception t) {
                        debug("createSftpClient({}) failed ({}) to close client: {}",
                                session, t.getClass().getSimpleName(), t.getMessage(), t);
                        err = GenericUtils.accumulateException(err, t);
                    }
                }
            }
        } catch (Exception e) {
            err = GenericUtils.accumulateException(err, e);
        }

        // This point is reached if error occurred
        log.warn("createSftpClient({}) failed ({}) to create client: {}",
                session, err.getClass().getSimpleName(), err.getMessage());

        try {
            session.close();
        } catch (Exception e) {
            debug("createSftpClient({}) failed ({}) to close session: {}",
                    session, e.getClass().getSimpleName(), e.getMessage(), e);
            err = GenericUtils.accumulateException(err, e);
        }

        if (err instanceof IOException) {
            throw (IOException) err;
        } else {
            throw new IOException(err);
        }
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
