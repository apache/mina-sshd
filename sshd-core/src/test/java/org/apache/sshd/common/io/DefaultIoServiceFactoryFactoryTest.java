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

import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DefaultIoServiceFactoryFactoryTest extends BaseTestSupport {
    public DefaultIoServiceFactoryFactoryTest() {
        super();
    }

    @Test
    public void testBuiltinIoServiceFactoryFactories() {
        for (BuiltinIoServiceFactoryFactories f : BuiltinIoServiceFactoryFactories.VALUES) {
            String name = f.getName();
            IoServiceFactoryFactory factoryInstance =
                    DefaultIoServiceFactoryFactory.newInstance(IoServiceFactoryFactory.class, name);
            Class<?> expected = f.getFactoryClass();
            Class<?> actual = factoryInstance.getClass();
            assertSame(name, expected, actual);
        }
    }

    @SuppressWarnings("boxing")
    @Test
    public void testExecutorServiceInitialization() throws IOException {
        ExecutorService service = Mockito.mock(ExecutorService.class);
        Mockito.when(service.shutdownNow()).thenReturn(Collections.<Runnable>emptyList());
        Mockito.when(service.isShutdown()).thenReturn(Boolean.TRUE);
        Mockito.when(service.isTerminated()).thenReturn(Boolean.TRUE);

        FactoryManager manager = Mockito.mock(FactoryManager.class);
        Mockito.when(manager.getProperties()).thenReturn(Collections.<String, Object>emptyMap());

        String propName = IoServiceFactoryFactory.class.getName();
        for (BuiltinIoServiceFactoryFactories f : BuiltinIoServiceFactoryFactories.VALUES) {
            String name = f.getName();
            try {
                System.setProperty(propName, name);
                for (boolean shutdownOnExit : new boolean[]{true, false}) {
                    DefaultIoServiceFactoryFactory defaultFactory = new DefaultIoServiceFactoryFactory(service, shutdownOnExit);

                    try (IoServiceFactory factory = defaultFactory.create(manager)) {
                        assertObjectInstanceOf(name + "/" + shutdownOnExit + " no executor service configuration", ExecutorServiceCarrier.class, factory);

                        ExecutorServiceCarrier carrier = (ExecutorServiceCarrier) factory;
                        assertSame(name + "/" + shutdownOnExit + " - mismatched executor service", service, carrier.getExecutorService());
                        assertEquals(name + "/" + shutdownOnExit + " - mismatched shutdown on exit", shutdownOnExit, carrier.isShutdownOnExit());
                    }
                }
            } finally {
                System.clearProperty(propName);
            }
        }
    }
}
