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

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DefaultSshFutureTest extends BaseTestSupport {
    public DefaultSshFutureTest() {
        super();
    }

    @Test
    @SuppressWarnings("rawtypes")
    public void testAwaitUninterrupted() {
        final DefaultSshFuture future = new DefaultSshFuture(null);
        final Object expected = new Object();
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
        assertSame("Mismatched signalled value", expected, future.getValue());
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void testNotifyMultipleListeners() {
        final DefaultSshFuture future = new DefaultSshFuture(null);
        final AtomicInteger listenerCount = new AtomicInteger(0);
        final Object expected = new Object();
        final SshFutureListener listener = new SshFutureListener() {
            @Override
            public void operationComplete(SshFuture f) {
                assertSame("Mismatched future instance", future, f);
                assertSame("Mismatched value object", expected, future.getValue());
                listenerCount.incrementAndGet();
            }
        };

        final int numListeners = Byte.SIZE;
        for (int index = 0; index < numListeners; index++) {
            future.addListener(listener);
        }

        future.setValue(expected);
        assertEquals("Mismatched listeners invocation count", numListeners, listenerCount.get());
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void testListenerInvokedDirectlyAfterResultSet() {
        final DefaultSshFuture future = new DefaultSshFuture(null);
        final AtomicInteger listenerCount = new AtomicInteger(0);
        final Object expected = new Object();
        final SshFutureListener listener = new SshFutureListener() {
            @Override
            public void operationComplete(SshFuture f) {
                assertSame("Mismatched future instance", future, f);
                assertSame("Mismatched value object", expected, future.getValue());
                listenerCount.incrementAndGet();
            }
        };
        future.setValue(expected);

        future.addListener(listener);
        assertEquals("Mismatched number of registered listeners", 0, future.getNumRegisteredListeners());
        assertEquals("Listener not invoked", 1, listenerCount.get());
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void testAddAndRemoveRegisteredListenersBeforeResultSet() {
        DefaultSshFuture future = new DefaultSshFuture(null);
        SshFutureListener listener = Mockito.mock(SshFutureListener.class);
        for (int index = 1; index <= Byte.SIZE; index++) {
            future.addListener(listener);
            assertEquals("Mismatched number of added listeners", index, future.getNumRegisteredListeners());
        }

        for (int index = future.getNumRegisteredListeners() - 1; index >= 0; index--) {
            future.removeListener(listener);
            assertEquals("Mismatched number of remaining listeners", index, future.getNumRegisteredListeners());
        }
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void testListenerNotRemovedIfResultSet() {
        final DefaultSshFuture future = new DefaultSshFuture(null);
        final AtomicInteger listenerCount = new AtomicInteger(0);
        final Object expected = new Object();
        final SshFutureListener listener = new SshFutureListener() {
            @Override
            public void operationComplete(SshFuture f) {
                assertSame("Mismatched future instance", future, f);
                assertSame("Mismatched value object", expected, future.getValue());
                listenerCount.incrementAndGet();
            }
        };
        future.addListener(listener);
        future.setValue(expected);
        assertEquals("Mismatched number of registered listeners", 1, future.getNumRegisteredListeners());
        assertEquals("Listener not invoked", 1, listenerCount.get());

        future.removeListener(listener);
        assertEquals("Mismatched number of remaining listeners", 1, future.getNumRegisteredListeners());
    }
}
