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

package org.apache.sshd.common.util.closeable;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class CloseableUtilsTest extends JUnitTestSupport {
    public CloseableUtilsTest() {
        super();
    }

    @Test
    public void testCloseImmediateNotCalledIfAlreadyClosed() throws IOException {
        Closeable closeable = new IoBaseCloseable() {
            @Override
            public CloseFuture close(boolean immediately) {
                fail("Unexpected call to close(" + immediately + ")");
                return null;
            }

            @Override
            public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                fail("Unexpected call to addCloseFutureListener");
            }

            @Override
            public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                fail("Unexpected call to removeCloseFutureListener");
            }

            @Override
            public boolean isClosed() {
                return true;
            }

            @Override
            public boolean isClosing() {
                return false;
            }
        };
        closeable.close();
    }

    @Test
    public void testCloseImmediateNotCalledIfIsClosing() throws IOException {
        Closeable closeable = new IoBaseCloseable() {
            @Override
            public CloseFuture close(boolean immediately) {
                fail("Unexpected call to close(" + immediately + ")");
                return null;
            }

            @Override
            public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                fail("Unexpected call to addCloseFutureListener");
            }

            @Override
            public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                fail("Unexpected call to removeCloseFutureListener");
            }

            @Override
            public boolean isClosed() {
                return false;
            }

            @Override
            public boolean isClosing() {
                return true;
            }
        };
        closeable.close();
    }

    @Test
    public void testCloseImmediateCalledAndWait() throws Exception {
        DefaultCloseFuture future = new DefaultCloseFuture(this, this);
        AtomicInteger callsCount = new AtomicInteger(0);
        Closeable closeable = new IoBaseCloseable() {
            @Override
            public CloseFuture close(boolean immediately) {
                assertTrue("Closure is not immediate", immediately);
                assertEquals("Multiple close immediate calls", 1, callsCount.incrementAndGet());
                return future;
            }

            @Override
            public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                fail("Unexpected call to addCloseFutureListener");
            }

            @Override
            public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                fail("Unexpected call to removeCloseFutureListener");
            }

            @Override
            public boolean isClosed() {
                return false;
            }

            @Override
            public boolean isClosing() {
                return false;
            }
        };

        ExecutorService service = ThreadUtils.newSingleThreadExecutor(getCurrentTestName());
        try {
            Future<?> task = service.submit((Runnable) () -> {
                try {
                    closeable.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            future.setClosed(); // signal close complete
            task.get(5L, TimeUnit.SECONDS); // make sure #await call terminated
            assertEquals("Close immediate not called", 1, callsCount.get());
        } finally {
            service.shutdownNow();
        }
    }
}
