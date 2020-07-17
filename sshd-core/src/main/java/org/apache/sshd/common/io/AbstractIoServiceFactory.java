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

package org.apache.sshd.common.io;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerHolder;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractIoServiceFactory
        extends AbstractCloseable
        implements IoServiceFactory, FactoryManagerHolder, ExecutorServiceCarrier {

    private IoServiceEventListener eventListener;
    private final FactoryManager manager;
    private final CloseableExecutorService executor;

    protected AbstractIoServiceFactory(FactoryManager factoryManager, CloseableExecutorService executorService) {
        manager = Objects.requireNonNull(factoryManager, "No factory manager provided");
        executor = Objects.requireNonNull(executorService, "No executor service provided");
        eventListener = factoryManager.getIoServiceEventListener();
    }

    @Override
    public final FactoryManager getFactoryManager() {
        return manager;
    }

    @Override
    public final CloseableExecutorService getExecutorService() {
        return executor;
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
    protected void doCloseImmediately() {
        try {
            CloseableExecutorService service = getExecutorService();
            if ((service != null) && (!service.isShutdown())) {
                log.debug("Shutdown executor");
                service.shutdownNow();
                if (service.awaitTermination(5, TimeUnit.SECONDS)) {
                    log.debug("Shutdown complete");
                } else {
                    log.debug("Not all tasks terminated");
                }
            }
        } catch (Exception e) {
            log.debug("Exception caught while closing executor", e);
        } finally {
            super.doCloseImmediately();
        }
    }

    protected <S extends IoService> S autowireCreatedService(S service) {
        if (service == null) {
            return service;
        }

        service.setIoServiceEventListener(getIoServiceEventListener());
        return service;
    }

    public static int getNioWorkers(FactoryManager manager) {
        return CoreModuleProperties.NIO_WORKERS.getRequired(manager);
    }
}
