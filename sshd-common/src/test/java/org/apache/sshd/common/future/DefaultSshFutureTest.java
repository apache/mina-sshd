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
package org.apache.sshd.common.future;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class DefaultSshFutureTest extends JUnitTestSupport {
    public DefaultSshFutureTest() {
        super();
    }

    @Test
    @SuppressWarnings("rawtypes")
    void awaitUninterrupted() {
        DefaultSshFuture future = new DefaultSshFuture(getCurrentTestName(), null);
        Object expected = new Object();
        new Thread() {
            @Override
            public void run() {
                try {
                    Thread.sleep(TimeUnit.SECONDS.toMillis(2L));
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                future.setValue(expected);
            }
        }.start();

        future.awaitUninterruptibly();
        assertSame(expected, future.getValue(), "Mismatched signalled value");
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void notifyMultipleListeners() {
        DefaultSshFuture future = new DefaultSshFuture(getCurrentTestName(), null);
        AtomicInteger listenerCount = new AtomicInteger(0);
        Object expected = new Object();
        SshFutureListener listener = f -> {
            assertSame(future, f, "Mismatched future instance");
            assertSame(expected, future.getValue(), "Mismatched value object");
            listenerCount.incrementAndGet();
        };

        int numListeners = Byte.SIZE;
        for (int index = 0; index < numListeners; index++) {
            future.addListener(listener);
        }

        future.setValue(expected);
        assertEquals(numListeners, listenerCount.get(), "Mismatched listeners invocation count");
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void listenerInvokedDirectlyAfterResultSet() {
        DefaultSshFuture future = new DefaultSshFuture(getCurrentTestName(), null);
        AtomicInteger listenerCount = new AtomicInteger(0);
        Object expected = new Object();
        SshFutureListener listener = f -> {
            assertSame(future, f, "Mismatched future instance");
            assertSame(expected, future.getValue(), "Mismatched value object");
            listenerCount.incrementAndGet();
        };
        future.setValue(expected);

        future.addListener(listener);
        assertEquals(0, future.getNumRegisteredListeners(), "Mismatched number of registered listeners");
        assertEquals(1, listenerCount.get(), "Listener not invoked");
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void addAndRemoveRegisteredListenersBeforeResultSet() {
        DefaultSshFuture future = new DefaultSshFuture(getCurrentTestName(), null);
        SshFutureListener listener = Mockito.mock(SshFutureListener.class);
        for (int index = 1; index <= Byte.SIZE; index++) {
            future.addListener(listener);
            assertEquals(index, future.getNumRegisteredListeners(), "Mismatched number of added listeners");
        }

        for (int index = future.getNumRegisteredListeners() - 1; index >= 0; index--) {
            future.removeListener(listener);
            assertEquals(index, future.getNumRegisteredListeners(), "Mismatched number of remaining listeners");
        }
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void listenerNotRemovedIfResultSet() {
        DefaultSshFuture future = new DefaultSshFuture(getCurrentTestName(), null);
        AtomicInteger listenerCount = new AtomicInteger(0);
        Object expected = new Object();
        SshFutureListener listener = f -> {
            assertSame(future, f, "Mismatched future instance");
            assertSame(expected, future.getValue(), "Mismatched value object");
            listenerCount.incrementAndGet();
        };
        future.addListener(listener);
        future.setValue(expected);
        assertEquals(1, future.getNumRegisteredListeners(), "Mismatched number of registered listeners");
        assertEquals(1, listenerCount.get(), "Listener not invoked");

        future.removeListener(listener);
        assertEquals(1, future.getNumRegisteredListeners(), "Mismatched number of remaining listeners");
    }
}
