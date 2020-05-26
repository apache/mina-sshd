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

import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.concurrent.Future;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NettyIoServiceFactory extends AbstractCloseable implements IoServiceFactory {

    protected final EventLoopGroup eventLoopGroup;
    protected final boolean closeEventLoopGroup;

    private IoServiceEventListener eventListener;

    public NettyIoServiceFactory() {
        this(null);
    }

    public NettyIoServiceFactory(EventLoopGroup group) {
        this.eventLoopGroup = (group != null) ? group : new NioEventLoopGroup();
        this.closeEventLoopGroup = group == null;
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
    public IoConnector createConnector(IoHandler handler) {
        return new NettyIoConnector(this, handler);
    }

    @Override
    public IoAcceptor createAcceptor(IoHandler handler) {
        return new NettyIoAcceptor(this, handler);
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        if (closeEventLoopGroup) {
            Future<?> shutdownFuture = eventLoopGroup.shutdownGracefully();
            shutdownFuture.addListener(fut -> closeFuture.setClosed());
        } else {
            closeFuture.setClosed();
        }
        return closeFuture;
    }

    @Override
    protected void doCloseImmediately() {
        doCloseGracefully();
        super.doCloseImmediately();
    }
}
