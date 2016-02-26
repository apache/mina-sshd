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

package org.apache.sshd.server.command;

import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ScpCommandFactoryTest extends BaseTestSupport {
    public ScpCommandFactoryTest() {
        super();
    }

    /**
     * Make sure that the builder returns a factory with the default values
     * if no {@code withXXX} method is invoked
     */
    @Test
    public void testBuilderDefaultFactoryValues() {
        ScpCommandFactory factory = new ScpCommandFactory.Builder().build();
        assertNull("Mismatched delegate", factory.getDelegateCommandFactory());
        assertNull("Mismatched executor", factory.getExecutorService());
        assertEquals("Mismatched send size", ScpHelper.MIN_SEND_BUFFER_SIZE, factory.getSendBufferSize());
        assertEquals("Mismatched receive size", ScpHelper.MIN_RECEIVE_BUFFER_SIZE, factory.getReceiveBufferSize());
        assertFalse("Mismatched shutdown state", factory.isShutdownOnExit());
    }

    /**
     * Make sure that the builder initializes correctly the built factory
     */
    @Test
    public void testBuilderCorrectlyInitializesFactory() {
        CommandFactory delegate = dummyFactory();
        ExecutorService service = dummyExecutor();
        int receiveSize = Short.MAX_VALUE;
        int sendSize = receiveSize + Long.SIZE;
        ScpCommandFactory factory = new ScpCommandFactory.Builder()
                .withDelegate(delegate)
                .withExecutorService(service)
                .withSendBufferSize(sendSize)
                .withReceiveBufferSize(receiveSize)
                .withShutdownOnExit(true)
                .build();
        assertSame("Mismatched delegate", delegate, factory.getDelegateCommandFactory());
        assertSame("Mismatched executor", service, factory.getExecutorService());
        assertEquals("Mismatched send size", sendSize, factory.getSendBufferSize());
        assertEquals("Mismatched receive size", receiveSize, factory.getReceiveBufferSize());
        assertTrue("Mismatched shutdown state", factory.isShutdownOnExit());
    }

    /**
     * <UL>
     * <LI>
     * Make sure the builder returns new instances on every call to
     * {@link org.apache.sshd.server.scp.ScpCommandFactory.Builder#build()} method
     * </LI>
     *
     * <LI>
     * Make sure values are preserved between successive invocations
     * of the {@link org.apache.sshd.server.scp.ScpCommandFactory.Builder#build()} method
     * </LI>
     * </UL
     */
    @Test
    public void testBuilderUniqueInstance() {
        ScpCommandFactory.Builder builder = new ScpCommandFactory.Builder();
        ScpCommandFactory f1 = builder.withDelegate(dummyFactory()).build();
        ScpCommandFactory f2 = builder.build();
        assertNotSame("No new instance built", f1, f2);
        assertSame("Mismatched delegate", f1.getDelegateCommandFactory(), f2.getDelegateCommandFactory());

        ScpCommandFactory f3 = builder.withDelegate(dummyFactory()).build();
        assertNotSame("Delegate not changed", f1.getDelegateCommandFactory(), f3.getDelegateCommandFactory());
    }

    private static ExecutorService dummyExecutor() {
        return Mockito.mock(ExecutorService.class);
    }

    private static CommandFactory dummyFactory() {
        return Mockito.mock(CommandFactory.class);
    }
}
