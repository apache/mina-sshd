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
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.helpers.MissingAttachedSessionException;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
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
                if (future.getSession() != NettyIoSession.this) {
                    close(true);
                }
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
            Channel channel = ctx.channel();
            Attribute<IoConnectFuture> connectFuture = channel.attr(NettyIoService.CONNECT_FUTURE_KEY);
            IoConnectFuture future = connectFuture.get();
            if (future != null) {
                // If the future wasn't fulfilled already cancel it.
                CancelFuture cancellation = future.cancel();
                if (cancellation != null) {
                    cancellation.setCanceled();
                }
            }
            context = null;
        }
    }

    protected void channelRead(ChannelHandlerContext ctx, Readable msg) throws Exception {
        handler.messageReceived(NettyIoSession.this, msg);
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
     * Netty adapter to use as a bridge, with extra handling for suspending reads. Netty may sometimes may deliver read
     * events even after reads have been suspended. Suspending reads only removes the channel for OP_READ in the next
     * select. But Netty's default read buffer management does not account for this, and it may deliver more events
     * still if there are more than 64kB available on the socket.
     * <p>
     * There is a {@link io.netty.handler.flow.FlowControlHandler} that should be able to handle this case if inserted
     * in the channel pipeline before this handler. But somehow this did not work reliably. Therefore this adapter
     * manages this directly by accumulating all read events in a single buffer and delivering the whole buffer once the
     * low-level socket read is completed.
     * </p>
     */
    protected class Adapter extends ChannelInboundHandlerAdapter {

        // Buffer for accumulating ByteBufs if we get multiple read events.
        private ByteArrayBuffer buffer;

        // The ByteBuf from the first (and single) read event, if there's only one. If a second event comes in, this
        // gets copied into buffer, released, and nulled out. This is an optimization to avoid needlessly copying
        // buffers.
        private ByteBuf ioBuffer;

        // Invariant: !(buffer != null && ioBuffer != null) Either they're both null (initially and on read complete),
        // or exactly one of them is non-null.

        public Adapter() {
            super();
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            NettyIoSession.this.channelActive(ctx);
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            buffer = null;
            if (ioBuffer != null) {
                ioBuffer.release();
                ioBuffer = null;
            }
            NettyIoSession.this.channelInactive(ctx);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            ByteBuf buf = (ByteBuf) msg;
            if (buffer == null) {
                if (ioBuffer == null) {
                    // First buffer; will be released in channelReadComplete() below, or when the second ByteBuf
                    // arrives.
                    ioBuffer = buf;
                    return;
                } else {
                    // Second ByteBuf: copy the ioBuffer, release and null it. Then copy buf and release it.
                    try {
                        buffer = new ByteArrayBuffer(ioBuffer.readableBytes() + buf.readableBytes(), false);
                        buffer.putBuffer(NettySupport.asReadable(ioBuffer), false);
                        buffer.putBuffer(NettySupport.asReadable(buf), false);
                    } finally {
                        ioBuffer.release();
                        ioBuffer = null;
                        buf.release();
                    }
                }
            } else {
                try {
                    buffer.putBuffer(NettySupport.asReadable(buf), true);
                } finally {
                    buf.release();
                }
            }
        }

        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
            // Clear fields before passing on the buffer, otherwise we might get into trouble if the session causes
            // another read.
            if (buffer != null) {
                ByteArrayBuffer buf = buffer;
                buffer = null;
                NettyIoSession.this.channelRead(ctx, buf);
            } else if (ioBuffer != null) {
                ByteBuf buf = ioBuffer;
                ioBuffer = null;
                try {
                    NettyIoSession.this.channelRead(ctx, NettySupport.asReadable(buf));
                } finally {
                    buf.release();
                }
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            NettyIoSession.this.exceptionCaught(ctx, cause);
        }
    }
}
