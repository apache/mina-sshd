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

package org.apache.sshd.common.io;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.CloseableUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractIoServiceFactory extends CloseableUtils.AbstractCloseable implements IoServiceFactory {

    protected final Logger logger;
    private final FactoryManager manager;
    private final ExecutorService executor;
    private final boolean shutdownExecutor;

    protected AbstractIoServiceFactory(FactoryManager factoryManager, ExecutorService executorService, boolean shutdownOnExit) {
        logger = LoggerFactory.getLogger(getClass());
        manager = factoryManager;
        executor = executorService;
        shutdownExecutor = shutdownOnExit;
    }

    public final FactoryManager getFactoryManager() {
        return manager;
    }

    public final ExecutorService getExecutorService() {
        return executor;
    }

    public final boolean isShutdownExecutor() {
        return shutdownExecutor;
    }

    @Override
    protected void doCloseImmediately() {
        try {
            ExecutorService service = getExecutorService();
            if ((service != null) && isShutdownExecutor() && (!service.isShutdown())) {
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
        Map<String, String> properties = manager.getProperties();
        String nioWorkers = properties.get(FactoryManager.NIO_WORKERS);
        if ((nioWorkers != null) && (nioWorkers.length() > 0)) {
            int nb = Integer.parseInt(nioWorkers);
            if (nb > 0) {
                return nb;
            }
        }

        return FactoryManager.DEFAULT_NIO_WORKERS;
    }
}
