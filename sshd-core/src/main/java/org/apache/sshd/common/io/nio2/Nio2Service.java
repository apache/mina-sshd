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
import java.net.SocketOption;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.NetworkChannel;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.CloseableUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public abstract class Nio2Service extends CloseableUtils.AbstractInnerCloseable implements IoService {

    protected final Logger logger = LoggerFactory.getLogger(getClass());
    protected final FactoryManager manager;
    protected final IoHandler handler;
    protected final Map<Long, IoSession> sessions;
    protected final AtomicBoolean disposing = new AtomicBoolean();
    protected final AsynchronousChannelGroup group;

    protected Nio2Service(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        logger.debug("Creating {}", getClass().getSimpleName());
        this.manager = manager;
        this.handler = handler;
        this.sessions = new ConcurrentHashMap<Long, IoSession>();
        this.group = group;
    }

    public void dispose() {
        try {
            close(true).await();
        } catch (InterruptedException e) {
            logger.debug("Exception caught while closing", e);
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().parallel(sessions.values()).build();
    }

    public Map<Long, IoSession> getManagedSessions() {
        return Collections.unmodifiableMap(sessions);
    }

    public void sessionClosed(Nio2Session session) {
        sessions.remove(session.getId());
    }

    protected <T> void setOption(NetworkChannel socket, String property, SocketOption<T> option, T defaultValue) throws IOException {
        String valStr = manager.getProperties().get(property);
        T val = defaultValue;
        if (valStr != null) {
            Class<T> type = option.type();
            if (type == Integer.class) {
                val = type.cast(Integer.parseInt(valStr));
            } else if (type == Boolean.class) {
                val = type.cast(Boolean.parseBoolean(valStr));
            } else {
                throw new IllegalStateException("Unsupported socket option type " + type);
            }
        }
        if (val != null) {
            try {
                socket.setOption(option, val);
            } catch (IOException e) {
                logger.warn("Unable to set socket option " + option + " to " + val, e);
            }
        }
    }

}
