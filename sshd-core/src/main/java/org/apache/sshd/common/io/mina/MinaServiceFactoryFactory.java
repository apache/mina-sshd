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

import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.AbstractIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactory;

/**
 */
public class MinaServiceFactoryFactory extends AbstractIoServiceFactoryFactory {
    public MinaServiceFactoryFactory() {
        this(null, true);
    }

    /**
     * @param executors      The {@link ExecutorService} to use for spawning threads.
     *                       If {@code null} then an internal service is allocated - in which case it
     *                       is automatically shutdown regardless of the value of the <tt>shutdownOnExit</tt>
     *                       parameter value
     * @param shutdownOnExit If {@code true} then the {@link ExecutorService#shutdownNow()}
     *                       will be called (unless it is an internally allocated service which is always
     *                       closed)
     */
    public MinaServiceFactoryFactory(ExecutorService executors, boolean shutdownOnExit) {
        super(executors, shutdownOnExit);
    }

    @Override
    public IoServiceFactory create(FactoryManager manager) {
        return new MinaServiceFactory(manager, getExecutorService(), isShutdownOnExit());
    }
}
