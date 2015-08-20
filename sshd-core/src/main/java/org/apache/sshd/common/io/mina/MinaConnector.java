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
package org.apache.sshd.common.io.mina;

import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoConnector;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoConnectFuture;

/**
 */
public class MinaConnector extends MinaService implements org.apache.sshd.common.io.IoConnector, IoHandler {

    protected final AtomicReference<IoConnector> connectorHolder = new AtomicReference<>(null);

    public MinaConnector(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler, IoProcessor<NioSession> ioProcessor) {
        super(manager, handler, ioProcessor);
    }

    protected IoConnector createConnector() {
        NioSocketConnector connector = new NioSocketConnector(ioProcessor);
        configure(connector.getSessionConfig());
        return connector;
    }

    protected IoConnector getConnector() {
        IoConnector connector;
        synchronized (connectorHolder) {
            connector = connectorHolder.get();
            if (connector != null) {
                return connector;
            }

            connector = createConnector();
            connector.setHandler(this);
            connectorHolder.set(connector);
        }

        log.debug("Created IoConnector");
        return connector;
    }

    @Override
    protected org.apache.mina.core.service.IoService getIoService() {
        return getConnector();
    }

    @Override
    public IoConnectFuture connect(SocketAddress address) {
        class Future extends DefaultSshFuture<IoConnectFuture> implements IoConnectFuture {
            Future(Object lock) {
                super(lock);
            }

            @Override
            public org.apache.sshd.common.io.IoSession getSession() {
                Object v = getValue();
                return v instanceof org.apache.sshd.common.io.IoSession ? (org.apache.sshd.common.io.IoSession) v : null;
            }

            @Override
            public Throwable getException() {
                Object v = getValue();
                return v instanceof Throwable ? (Throwable) v : null;
            }

            @Override
            public boolean isConnected() {
                return getValue() instanceof org.apache.sshd.common.io.IoSession;
            }

            @Override
            public void setSession(org.apache.sshd.common.io.IoSession session) {
                setValue(session);
            }

            @Override
            public void setException(Throwable exception) {
                setValue(exception);
            }
        }
        final IoConnectFuture future = new Future(null);
        getConnector().connect(address).addListener(new IoFutureListener<ConnectFuture>() {
            @Override
            public void operationComplete(ConnectFuture cf) {
                if (cf.getException() != null) {
                    future.setException(cf.getException());
                } else if (cf.isCanceled()) {
                    future.cancel();
                } else {
                    future.setSession(getSession(cf.getSession()));
                }
            }
        });
        return future;
    }

}
