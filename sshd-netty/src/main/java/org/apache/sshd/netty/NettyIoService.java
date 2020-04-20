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

package org.apache.sshd.netty;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import io.netty.channel.group.ChannelGroup;
import io.netty.util.AttributeKey;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class NettyIoService extends AbstractCloseable implements IoService {

    public static final AttributeKey<IoConnectFuture> CONNECT_FUTURE_KEY
            = AttributeKey.valueOf(IoConnectFuture.class.getName());
    public static final AttributeKey<AttributeRepository> CONTEXT_KEY
            = AttributeKey.valueOf(AttributeRepository.class.getName());

    protected final AtomicLong sessionSeq = new AtomicLong();
    protected final Map<Long, IoSession> sessions = new ConcurrentHashMap<>();
    protected ChannelGroup channelGroup;
    protected final NettyIoServiceFactory factory;
    protected final IoHandler handler;

    private IoServiceEventListener eventListener;

    protected NettyIoService(NettyIoServiceFactory factory, IoHandler handler) {
        this.factory = Objects.requireNonNull(factory, "No factory instance provided");
        this.handler = Objects.requireNonNull(handler, "No I/O handler provied");
        this.eventListener = factory.getIoServiceEventListener();
    }

    @Override
    public IoServiceEventListener getIoServiceEventListener() {
        return eventListener;
    }

    @Override
    public void setIoServiceEventListener(IoServiceEventListener listener) {
        eventListener = listener;
    }

    @Override
    public Map<Long, IoSession> getManagedSessions() {
        return sessions;
    }
}
