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

import java.nio.channels.AsynchronousChannel;
import java.util.Objects;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.AbstractIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.util.threads.CloseableExecutorService;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2ServiceFactoryFactory extends AbstractIoServiceFactoryFactory {
    public Nio2ServiceFactoryFactory() {
        this(null);
    }

    /**
     * @param executors The {@link CloseableExecutorService} to use for spawning threads. If {@code null} then an
     *                  internal service is allocated - in which case it is automatically shutdown
     */
    public Nio2ServiceFactoryFactory(Factory<CloseableExecutorService> executors) {
        super(executors);
        // Make sure NIO2 is available
        Objects.requireNonNull(AsynchronousChannel.class, "Missing NIO2 class");
    }

    @Override
    public IoServiceFactory create(FactoryManager manager) {
        return new Nio2ServiceFactory(manager, newExecutor());
    }
}
