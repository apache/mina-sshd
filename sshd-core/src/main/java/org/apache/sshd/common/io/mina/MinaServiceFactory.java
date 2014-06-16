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
package org.apache.sshd.common.io.mina;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.SimpleIoProcessorPool;
import org.apache.mina.transport.socket.nio.NioProcessor;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.ThreadUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public class MinaServiceFactory extends CloseableUtils.AbstractCloseable implements IoServiceFactory {

    private final Logger logger = LoggerFactory.getLogger(MinaServiceFactory.class);
    private final FactoryManager manager;
    private final ExecutorService executor;
    private final IoProcessor<NioSession> ioProcessor;

    public MinaServiceFactory(FactoryManager manager) {
        this.manager = manager;
        this.executor = ThreadUtils.newCachedThreadPool(manager.toString() + "-mina");
        this.ioProcessor = new SimpleIoProcessorPool<NioSession>(NioProcessor.class, getNioWorkers());
    }

    public IoConnector createConnector(IoHandler handler) {
        return new MinaConnector(manager, handler, ioProcessor);
    }

    public IoAcceptor createAcceptor(IoHandler handler) {
        return new MinaAcceptor(manager, handler, ioProcessor);
    }

    @Override
    protected void doCloseImmediately() {
        try {
            executor.shutdownNow();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.debug("Exception caught while closing executor", e);
        } finally {
            super.doCloseImmediately();
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

}
