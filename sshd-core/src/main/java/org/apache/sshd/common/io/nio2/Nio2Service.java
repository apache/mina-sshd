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
package org.apache.sshd.common.io.nio2;

import java.io.IOException;
import java.net.SocketOption;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.NetworkChannel;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 */
public abstract class Nio2Service extends CloseableUtils.AbstractInnerCloseable implements IoService {
    protected final FactoryManager manager;
    protected final IoHandler handler;
    protected final Map<Long, IoSession> sessions;
    protected final AtomicBoolean disposing = new AtomicBoolean();
    protected final AsynchronousChannelGroup group;

    protected Nio2Service(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        log.trace("Creating {}", getClass().getSimpleName());
        this.manager = ValidateUtils.checkNotNull(manager, "No factory manager provided");
        this.handler = ValidateUtils.checkNotNull(handler, "No I/O handler provided");
        this.group = ValidateUtils.checkNotNull(group, "No async. channel group provided");
        this.sessions = new ConcurrentHashMap<>();
    }

    public void dispose() {
        try {
            close(true).await();    // TODO use verify+(configurable) timeout
        } catch (IOException e) {
            log.debug("Exception caught while closing", e);
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().parallel(sessions.values()).build();
    }

    @Override
    public Map<Long, IoSession> getManagedSessions() {
        return Collections.unmodifiableMap(sessions);
    }

    public void sessionClosed(Nio2Session session) {
        sessions.remove(session.getId());
    }

    protected <T> void setOption(NetworkChannel socket, String property, SocketOption<T> option, T defaultValue) throws IOException {
        String valStr = FactoryManagerUtils.getString(manager, property);
        T val = defaultValue;
        if (!GenericUtils.isEmpty(valStr)) {
            Class<T> type = option.type();
            if (type == Integer.class) {
                val = type.cast(Integer.valueOf(valStr));
            } else if (type == Boolean.class) {
                val = type.cast(Boolean.valueOf(valStr));
            } else {
                throw new IllegalStateException("Unsupported socket option type " + type);
            }
        }

        if (val != null) {
            Collection<? extends SocketOption<?>> supported = socket.supportedOptions();
            if ((GenericUtils.size(supported) <= 0) || (!supported.contains(option))) {
                log.warn("Unsupported socket option (" + option + ") to set using property '" + property + "' value=" + val);
                return;
            }

            try {
                socket.setOption(option, val);
                if (log.isDebugEnabled()) {
                    log.debug("setOption({})[{}] from property={}", option, val, property);
                }
            } catch (IOException | RuntimeException e) {
                log.warn("Unable (" + e.getClass().getSimpleName() + ")"
                       + " to set socket option " + option
                       + " using property '" + property + "' value=" + val
                       + ": " + e.getMessage());
            }
        }
    }
}
