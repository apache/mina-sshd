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

import java.io.IOException;
import java.nio.channels.AsynchronousChannelGroup;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.io.AbstractIoServiceFactory;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2ServiceFactory extends AbstractIoServiceFactory {

    private final AsynchronousChannelGroup group;

    public Nio2ServiceFactory(FactoryManager factoryManager, CloseableExecutorService service) {
        super(factoryManager,
              ThreadUtils.newFixedThreadPoolIf(service, factoryManager.toString() + "-nio2", getNioWorkers(factoryManager)));
        try {
            group = AsynchronousChannelGroup.withThreadPool(ThreadUtils.noClose(getExecutorService()));
        } catch (IOException e) {
            warn("Failed ({}) to start async. channel group: {}", e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }
    }

    @Override
    public IoConnector createConnector(IoHandler handler) {
        return autowireCreatedService(new Nio2Connector(getFactoryManager(), handler, group));
    }

    @Override
    public IoAcceptor createAcceptor(IoHandler handler) {
        return autowireCreatedService(new Nio2Acceptor(getFactoryManager(), handler, group));
    }

    @Override
    protected void doCloseImmediately() {
        try {
            if (!group.isShutdown()) {
                log.debug("Shutdown group");
                group.shutdownNow();

                // if we protect the executor then the await will fail since we didn't really shut it down...
                if (group.awaitTermination(5, TimeUnit.SECONDS)) {
                    log.debug("Group successfully shut down");
                } else {
                    log.debug("Not all group tasks terminated");
                }
            }
        } catch (Exception e) {
            log.debug("Exception caught while closing channel group", e);
        } finally {
            super.doCloseImmediately();
        }
    }
}
