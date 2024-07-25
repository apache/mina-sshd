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

package org.apache.sshd.scp.server;

import java.util.function.Supplier;

import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ScpCommandFactoryTest extends BaseTestSupport {
    public ScpCommandFactoryTest() {
        super();
    }

    /**
     * Make sure that the builder returns a factory with the default values if no {@code withXXX} method is invoked
     */
    @Test
    void builderDefaultFactoryValues() {
        ScpCommandFactory factory = new ScpCommandFactory.Builder().build();
        assertNull(factory.getDelegateCommandFactory(), "Mismatched delegate");
        assertNull(factory.getExecutorServiceProvider(), "Mismatched executor");
        assertEquals(ScpHelper.DEFAULT_SEND_BUFFER_SIZE, factory.getSendBufferSize(), "Mismatched send size");
        assertEquals(ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE, factory.getReceiveBufferSize(), "Mismatched receive size");
    }

    /**
     * Make sure that the builder initializes correctly the built factory
     */
    @Test
    void builderCorrectlyInitializesFactory() {
        CommandFactory delegate = dummyFactory();
        CloseableExecutorService service = dummyExecutor();
        Supplier<CloseableExecutorService> provider = () -> service;
        int receiveSize = Short.MAX_VALUE;
        int sendSize = receiveSize + Long.SIZE;
        ScpCommandFactory factory = new ScpCommandFactory.Builder()
                .withDelegate(delegate)
                .withExecutorServiceProvider(provider)
                .withSendBufferSize(sendSize)
                .withReceiveBufferSize(receiveSize)
                .build();
        assertSame(delegate, factory.getDelegateCommandFactory(), "Mismatched delegate");
        assertSame(provider, factory.getExecutorServiceProvider(), "Mismatched executor");
        assertEquals(sendSize, factory.getSendBufferSize(), "Mismatched send size");
        assertEquals(receiveSize, factory.getReceiveBufferSize(), "Mismatched receive size");
    }

    /**
     * <UL>
     * <LI>Make sure the builder returns new instances on every call to {@link ScpCommandFactory.Builder#build()}
     * method</LI>
     *
     * <LI>Make sure values are preserved between successive invocations of the
     * {@link ScpCommandFactory.Builder#build()} method</LI> </UL
     */
    @Test
    void builderUniqueInstance() {
        ScpCommandFactory.Builder builder = new ScpCommandFactory.Builder();
        ScpCommandFactory f1 = builder.withDelegate(dummyFactory()).build();
        ScpCommandFactory f2 = builder.build();
        assertNotSame(f1, f2, "No new instance built");
        assertSame(f1.getDelegateCommandFactory(), f2.getDelegateCommandFactory(), "Mismatched delegate");

        ScpCommandFactory f3 = builder.withDelegate(dummyFactory()).build();
        assertNotSame(f1.getDelegateCommandFactory(), f3.getDelegateCommandFactory(), "Delegate not changed");
    }

    private static CloseableExecutorService dummyExecutor() {
        return Mockito.mock(CloseableExecutorService.class);
    }

    private static CommandFactory dummyFactory() {
        return Mockito.mock(CommandFactory.class);
    }
}
