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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerHolder;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractIoServiceFactory
                extends AbstractCloseable
                implements IoServiceFactory, FactoryManagerHolder, ExecutorServiceCarrier {

    private final FactoryManager manager;
    private final ExecutorService executor;
    private final boolean shutdownExecutor;

    protected AbstractIoServiceFactory(FactoryManager factoryManager, ExecutorService executorService, boolean shutdownOnExit) {
        manager = factoryManager;
        executor = executorService;
        shutdownExecutor = shutdownOnExit;
    }

    @Override
    public final FactoryManager getFactoryManager() {
        return manager;
    }

    @Override
    public final ExecutorService getExecutorService() {
        return executor;
    }

    @Override
    public final boolean isShutdownOnExit() {
        return shutdownExecutor;
    }

    @Override
    protected void doCloseImmediately() {
        try {
            ExecutorService service = getExecutorService();
            if ((service != null) && isShutdownOnExit() && (!service.isShutdown())) {
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

    public static int getNioWorkers(FactoryManager manager) {
        int nb = PropertyResolverUtils.getIntProperty(manager, FactoryManager.NIO_WORKERS, FactoryManager.DEFAULT_NIO_WORKERS);
        if (nb > 0) {
            return nb;
        } else {
            return FactoryManager.DEFAULT_NIO_WORKERS;
        }
    }
}
