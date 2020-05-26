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

import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SimpleCloseable extends IoBaseCloseable {

    protected final DefaultCloseFuture future;
    protected final AtomicBoolean closing;

    public SimpleCloseable(Object id, Object lock) {
        future = new DefaultCloseFuture(id, lock);
        closing = new AtomicBoolean(false);
    }

    @Override
    public boolean isClosed() {
        return future.isClosed();
    }

    @Override
    public boolean isClosing() {
        return closing.get();
    }

    @Override
    public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
        future.addListener(listener);
    }

    @Override
    public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
        future.removeListener(listener);
    }

    @Override
    public CloseFuture close(boolean immediately) {
        if (closing.compareAndSet(false, true)) {
            doClose(immediately);
        }
        return future;
    }

    protected void doClose(boolean immediately) {
        future.setClosed();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + future + "]";
    }
}
