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

import java.io.IOException;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.socket.DuplexChannel;
import io.netty.util.Attribute;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.helpers.MissingAttachedSessionException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * The Netty based IoSession implementation.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NettyIoSession extends AbstractCloseable implements IoSession {

    protected final Map<Object, Object> attributes = new HashMap<>();
    protected final NettyIoService service;
    protected final IoHandler handler;
    protected final long id;
    protected volatile ChannelHandlerContext context;
    protected SocketAddress remoteAddr;
    protected ChannelFuture prev;
    protected final ChannelInboundHandlerAdapter adapter = new Adapter();
    protected final AtomicBoolean readSuspended = new AtomicBoolean();

    private final SocketAddress acceptanceAddress;

    public NettyIoSession(NettyIoService service, IoHandler handler, SocketAddress acceptanceAddress) {
        super(Objects.toString(acceptanceAddress, ""));

        this.service = service;
        this.handler = handler;
        this.id = service.sessionSeq.incrementAndGet();
        this.acceptanceAddress = acceptanceAddress;
    }

    @Override
    public long getId() {
        return id;
    }

    @Override
    public Object getAttribute(Object key) {
        synchronized (attributes) {
            return attributes.get(key);
        }
    }

    @Override
    public Object setAttribute(Object key, Object value) {
        synchronized (attributes) {
            return attributes.put(key, value);
        }
    }

    @Override
    public Object setAttributeIfAbsent(Object key, Object value) {
        synchronized (attributes) {
            return attributes.putIfAbsent(key, value);
        }
    }

    @Override
    public Object removeAttribute(Object key) {
        synchronized (attributes) {
            return attributes.remove(key);
        }
    }

    @Override
    public SocketAddress getRemoteAddress() {
        return remoteAddr;
    }

    @Override
    public SocketAddress getLocalAddress() {
        Channel channel = (context == null) ? null : context.channel();
        return (channel == null) ? null : channel.localAddress();
    }

    @Override
    public SocketAddress getAcceptanceAddress() {
        return acceptanceAddress;
    }

    @Override
    public IoWriteFuture writeBuffer(Buffer buffer) {
        int bufLen = buffer.available();
        ByteBuf buf = Unpooled.buffer(bufLen);
        buf.writeBytes(buffer.array(), buffer.rpos(), bufLen);
        DefaultIoWriteFuture msg = new DefaultIoWriteFuture(getRemoteAddress(), null);
        ChannelPromise next = context.newPromise();
        prev.addListener(whatever -> {
            ChannelHandlerContext ctx = context;
            if (ctx != null) {
                ctx.writeAndFlush(buf, next);
            }
        });
        prev = next;
        next.addListener(fut -> {
            if (fut.isSuccess()) {
                msg.setValue(Boolean.TRUE);
            } else {
                msg.setValue(fut.cause());
            }
        });
        return msg;
    }

    @Override
    public IoService getService() {
        return service;
    }

    @Override
    public void suspendRead() {
        if (!readSuspended.getAndSet(true)) {
            ChannelHandlerContext ctx = context;
            if (ctx != null) {
                Channel ch = ctx.channel();
                ch.config().setAutoRead(false);
            }
        }
    }

    @Override
    public void resumeRead() {
        if (readSuspended.getAndSet(false)) {
            ChannelHandlerContext ctx = context;
            if (ctx != null) {
                Channel ch = ctx.channel();
                ch.config().setAutoRead(true);
            }
        }
    }

    @Override // see SSHD-902
    public void shutdownOutputStream() throws IOException {
        ChannelHandlerContext ctx = context;
        if (ctx == null) {
            return;
        }
        Channel ch = ctx.channel();
        if (ch instanceof DuplexChannel) {
            ((DuplexChannel) ch).shutdownOutput();
        } else if (log.isDebugEnabled()) {
            log.debug("shutdownOutputStream({}) channel is not DuplexChannel: {}", this,
                    (ch == null) ? null : ch.getClass().getSimpleName());
        }
    }

    /**
     * Intended for tests simulating a sudden connection drop only! Do not call otherwise.
     */
    public void suspend() {
        // Invoked reflectively in org.apache.sshd.client.ClientTest
        ChannelHandlerContext ctx = context;
        if (ctx != null) {
            Channel ch = ctx.channel();
            if (ch != null) {
                ch.disconnect();
            }
        }
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        ChannelHandlerContext ctx = context;
        if (ctx != null) {
            ctx.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE)
                    .addListener(fut -> closeFuture.setClosed());
        } else {
            closeFuture.setClosed();
        }
        return closeFuture;
    }

    @Override
    protected void doCloseImmediately() {
        ChannelHandlerContext ctx = context;
        if (ctx != null) {
            ctx.close();
        }
        super.doCloseImmediately();
    }

    protected void channelActive(ChannelHandlerContext ctx) throws Exception {
        context = ctx;
        Channel channel = ctx.channel();
        service.channelGroup.add(channel);
        service.sessions.put(id, NettyIoSession.this);
        prev = context.newPromise().setSuccess();
        remoteAddr = channel.remoteAddress();
        // If handler.sessionCreated() propagates an exception, we'll have a NettyIoSession without SSH session. We'll
        // propagate the exception, exceptionCaught will be called, which won't find an SSH session to handle the
        // exception and propagate a MissingAttachedSessionException. However, Netty will swallow and log exceptions
        // propagated out of exceptionCaught. This will lead to follow-up exceptions.
        //
        // We have to close the NettyIoSession in this case.
        Attribute<IoConnectFuture> connectFuture = channel.attr(NettyIoService.CONNECT_FUTURE_KEY);
        IoConnectFuture future = connectFuture.get();
        try {
            handler.sessionCreated(NettyIoSession.this);
            if (future != null) {
                future.setSession(NettyIoSession.this);
            }
        } catch (Throwable e) {
            log.warn("channelActive(session={}): could not create SSH session ({}); closing", this, e.getClass().getName(), e);
            try {
                if (future != null) {
                    future.setException(e);
                }
            } finally {
                close(true);
            }
        }
    }

    protected void channelInactive(ChannelHandlerContext ctx) throws Exception {
        service.sessions.remove(id);
        try {
            handler.sessionClosed(NettyIoSession.this);
        } catch (MissingAttachedSessionException e) {
            // handler.sessionClosed() is supposed to close the attached SSH session. If there isn't one,
            // we don't care anymore at this point.
            if (log.isTraceEnabled()) {
                log.trace("channelInactive(session={}): caught {}", this, e.getClass().getName(), e);
            }
        } finally {
            context = null;
        }
    }

    protected void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf buf = (ByteBuf) msg;
        try {
            handler.messageReceived(NettyIoSession.this, NettySupport.asReadable(buf));
        } finally {
            buf.release();
        }
    }

    protected void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        handler.exceptionCaught(NettyIoSession.this, cause);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[local=" + getLocalAddress()
               + ", remote=" + getRemoteAddress()
               + "]";
    }

    protected static class DefaultIoWriteFuture extends AbstractIoWriteFuture {
        public DefaultIoWriteFuture(Object id, Object lock) {
            super(id, lock);
        }
    }

    /**
     * Simple netty adapter to use as a bridge.
     */
    protected class Adapter extends ChannelInboundHandlerAdapter {
        public Adapter() {
            super();
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            NettyIoSession.this.channelActive(ctx);
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            NettyIoSession.this.channelInactive(ctx);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            NettyIoSession.this.channelRead(ctx, msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            NettyIoSession.this.exceptionCaught(ctx, cause);
        }
    }
}
