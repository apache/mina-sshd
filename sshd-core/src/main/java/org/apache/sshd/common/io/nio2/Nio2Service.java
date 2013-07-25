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
package org.apache.sshd.common.io.nio2;

import java.io.IOException;
import java.nio.channels.AsynchronousChannelGroup;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public abstract class Nio2Service implements IoService {

    protected final Logger logger = LoggerFactory.getLogger(getClass());
    protected final FactoryManager manager;
    protected final IoHandler handler;
    protected final ExecutorService executor;
    protected final AsynchronousChannelGroup group;
    protected final Map<Long, IoSession> sessions;
    protected final AtomicBoolean disposing = new AtomicBoolean();

    protected Nio2Service(FactoryManager manager, IoHandler handler) {
        logger.debug("Creating {}", getClass().getSimpleName());
        try {
            this.manager = manager;
            this.handler = handler;
            executor = Executors.newFixedThreadPool(getNioWorkers());
            group = AsynchronousChannelGroup.withThreadPool(executor);
            sessions = new ConcurrentHashMap<Long, IoSession>();
        } catch (IOException e) {
            throw new RuntimeSshException(e);
        }
    }

    public int getNioWorkers() {
        String nioWorkers = manager.getProperties().get(FactoryManager.NIO_WORKERS);
        if (nioWorkers != null && nioWorkers.length() > 0) {
            int nb = Integer.parseInt(nioWorkers);
            if (nb > 0) {
                return nb;
            }
        }
        return FactoryManager.DEFAULT_NIO_WORKERS;
    }

    public void dispose() {
        if (disposing.compareAndSet(false, true)) {
            logger.debug("Disposing {}", getClass().getSimpleName());
            doDispose();
        }
    }

    protected void doDispose() {
        for (IoSession session : sessions.values()) {
            session.close(true);
        }
        group.shutdown();
    }

    public Map<Long, IoSession> getManagedSessions() {
        return Collections.unmodifiableMap(sessions);
    }

    public void sessionClosed(Nio2Session session) {
        sessions.remove(session.getId());
    }
}
