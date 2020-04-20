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

import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;

/**
 * @param  <T> Type of future
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FuturesCloseable<T extends SshFuture> extends SimpleCloseable {

    private final Iterable<? extends SshFuture<T>> futures;

    public FuturesCloseable(Object id, Object lock, Iterable<? extends SshFuture<T>> futures) {
        super(id, lock);
        this.futures = (futures == null) ? Collections.emptyList() : futures;
    }

    @Override
    protected void doClose(boolean immediately) {
        if (immediately) {
            for (SshFuture<?> f : futures) {
                if (f instanceof DefaultSshFuture) {
                    ((DefaultSshFuture<?>) f).setValue(new SshException("Closed"));
                }
            }
            future.setClosed();
        } else {
            AtomicInteger count = new AtomicInteger(1);
            boolean traceEnabled = log.isTraceEnabled();
            SshFutureListener<T> listener = f -> {
                int pendingCount = count.decrementAndGet();
                if (traceEnabled) {
                    log.trace("doClose(" + immediately + ") complete pending: " + pendingCount);
                }
                if (pendingCount == 0) {
                    future.setClosed();
                }
            };

            for (SshFuture<T> f : futures) {
                if (f != null) {
                    int pendingCount = count.incrementAndGet();
                    if (traceEnabled) {
                        log.trace("doClose(" + immediately + ") future pending: " + pendingCount);
                    }
                    f.addListener(listener);
                }
            }
            listener.operationComplete(null);
        }
    }
}
