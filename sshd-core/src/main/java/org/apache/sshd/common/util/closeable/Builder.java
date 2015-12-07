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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class Builder implements ObjectBuilder<Closeable> {

    private final Object lock;
    private final List<Closeable> closeables = new ArrayList<Closeable>();

    public Builder(Object lock) {
        this.lock = ValidateUtils.checkNotNull(lock, "No lock");
    }

    public Builder run(final Runnable r) {
        return close(new SimpleCloseable(lock) {
            @Override
            protected void doClose(boolean immediately) {
                try {
                    r.run();
                } finally {
                    super.doClose(immediately);
                }
            }
        });
    }

    @SuppressWarnings("rawtypes")
    public <T extends SshFuture> Builder when(SshFuture<T> future) {
        if (future != null) {
            when(Collections.singleton(future));
        }
        return this;
    }

    @SuppressWarnings("rawtypes")
    @SafeVarargs
    public final <T extends SshFuture> Builder when(SshFuture<T>... futures) {
        return when(Arrays.asList(futures));
    }

    @SuppressWarnings("rawtypes")
    public <T extends SshFuture> Builder when(final Iterable<? extends SshFuture<T>> futures) {
        return close(new FuturesCloseable<T>(lock, futures));
    }

    public Builder sequential(Closeable... closeables) {
        for (Closeable closeable : closeables) {
            close(closeable);
        }
        return this;
    }

    public Builder sequential(Iterable<Closeable> closeables) {
        return close(new SequentialCloseable(lock, closeables));
    }

    public Builder parallel(Closeable... closeables) {
        if (closeables.length == 1) {
            close(closeables[0]);
        } else if (closeables.length > 0) {
            parallel(Arrays.asList(closeables));
        }
        return this;
    }

    public Builder parallel(Iterable<? extends Closeable> closeables) {
        return close(new ParallelCloseable(lock, closeables));
    }

    public Builder close(Closeable c) {
        if (c != null) {
            closeables.add(c);
        }
        return this;
    }

    @Override
    public Closeable build() {
        if (closeables.isEmpty()) {
            return new SimpleCloseable(lock);
        } else if (closeables.size() == 1) {
            return closeables.get(0);
        } else {
            return new SequentialCloseable(lock, closeables);
        }
    }
}