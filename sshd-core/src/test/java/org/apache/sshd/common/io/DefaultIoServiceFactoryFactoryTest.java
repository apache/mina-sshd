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

import java.util.Collections;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class DefaultIoServiceFactoryFactoryTest extends BaseTestSupport {
    public DefaultIoServiceFactoryFactoryTest() {
        super();
    }

    @Test
    void builtinIoServiceFactoryFactories() {
        for (BuiltinIoServiceFactoryFactories f : BuiltinIoServiceFactoryFactories.VALUES) {
            if (!f.isSupported()) {
                continue;
            }
            String name = f.getName();
            IoServiceFactoryFactory factoryInstance
                    = DefaultIoServiceFactoryFactory.newInstance(IoServiceFactoryFactory.class, name);
            Class<?> expected = f.getFactoryClass();
            Class<?> actual = factoryInstance.getClass();
            assertSame(expected, actual, name);
        }
    }

    @SuppressWarnings("boxing")
    @Test
    void executorServiceInitialization() throws Exception {
        CloseableExecutorService service = Mockito.mock(CloseableExecutorService.class);
        Mockito.when(service.shutdownNow()).thenReturn(Collections.emptyList());
        Mockito.when(service.isShutdown()).thenReturn(Boolean.TRUE);
        Mockito.when(service.isTerminated()).thenReturn(Boolean.TRUE);

        FactoryManager manager = Mockito.mock(FactoryManager.class);
        Mockito.when(manager.getProperties()).thenReturn(Collections.emptyMap());

        String propName = IoServiceFactoryFactory.class.getName();
        for (BuiltinIoServiceFactoryFactories f : BuiltinIoServiceFactoryFactories.VALUES) {
            if (!f.isSupported()) {
                continue;
            }
            String name = f.getName();
            try {
                System.setProperty(propName, name);
                DefaultIoServiceFactoryFactory defaultFactory = new DefaultIoServiceFactoryFactory(() -> service);

                try (IoServiceFactory factory = defaultFactory.create(manager)) {

                    CloseableExecutorService svc
                            = (CloseableExecutorService) factory.getClass().getMethod("getExecutorService").invoke(factory);
                    assertSame(service, svc, name + " - mismatched executor service");
                } catch (NoSuchMethodException e) {
                    // ignore if there's no executor service
                }
            } finally {
                System.clearProperty(propName);
            }
        }
    }
}
