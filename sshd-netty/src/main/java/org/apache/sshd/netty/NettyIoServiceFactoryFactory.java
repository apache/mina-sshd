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

import java.util.Objects;

import io.netty.channel.EventLoopGroup;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.AbstractIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactory;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NettyIoServiceFactoryFactory extends AbstractIoServiceFactoryFactory {

    protected final EventLoopGroup eventLoopGroup;

    public NettyIoServiceFactoryFactory() {
        this(null);
    }

    public NettyIoServiceFactoryFactory(EventLoopGroup eventLoopGroup) {
        super(null);
        this.eventLoopGroup = eventLoopGroup;
    }

    @Override
    public IoServiceFactory create(FactoryManager manager) {
        Objects.requireNonNull(manager, "No factory manager provided");
        IoServiceFactory factory = new NettyIoServiceFactory(eventLoopGroup);
        factory.setIoServiceEventListener(manager.getIoServiceEventListener());
        return factory;
    }
}
