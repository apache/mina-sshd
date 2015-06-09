/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Utility class to help with {@link Closeable}s.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CloseableUtils {
    private CloseableUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    // TODO once JDK 8+ becomes the minimum for this project, make it a static method in the Closeable interface
    public static void close(Closeable closeable) throws IOException {
        if (closeable == null) {
            return;
        }

        if ((!closeable.isClosed()) && (!closeable.isClosing())) {
            CloseFuture future=closeable.close(true);
            try {
                future.await();
            } catch(InterruptedException e) {
                throw new InterruptedIOException(e.getClass().getSimpleName() + " while await future closure: " + e.getMessage());
            }
        }
    }

    public static CloseFuture closed() {
        CloseFuture future = new DefaultCloseFuture(null);
        future.setClosed();
        return future;
    }

    public static class Builder implements ObjectBuilder<Closeable> {

        private final Object lock;
        private final List<Closeable> closeables = new ArrayList<Closeable>();

        private Builder(Object lock) {
            this.lock = lock;
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
        public <T extends SshFuture> Builder when(@SuppressWarnings("unchecked") SshFuture<T>... futures) {
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

        @SuppressWarnings("synthetic-access")
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

    public static abstract class IoBaseCloseable extends AbstractLoggingBean implements Closeable {
        protected IoBaseCloseable() {
            super();
        }
        
        protected IoBaseCloseable(String discriminator) {
            super(discriminator);
        }

        // TODO once JDK 8+ becomes the minimum for this project, make it a default method instead of this class
        @Override
        public boolean isOpen() {
            if (isClosed() || isClosing()) {
                return false;
            } else {
                return true;
            }
        }

        // TODO once JDK 8+ becomes the minimum for this project, make it a default method instead of this class
        @Override
        public void close() throws IOException {
            CloseableUtils.close(this);
        }
    }

    private static class SimpleCloseable extends IoBaseCloseable {

        protected final DefaultCloseFuture future;
        protected final AtomicBoolean closing;

        public SimpleCloseable(Object lock) {
            future = new DefaultCloseFuture(lock);
            closing = new AtomicBoolean();
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
        public CloseFuture close(boolean immediately) {
            if (closing.compareAndSet(false, true)) {
                doClose(immediately);
            }
            return future;
        }

        protected void doClose(boolean immediately) {
            future.setClosed();
        }
    }

    private static class ParallelCloseable extends SimpleCloseable {

        private final Iterable<? extends Closeable> closeables;

        private ParallelCloseable(Object lock, Iterable<? extends Closeable> closeables) {
            super(lock);
            this.closeables = closeables;
        }

        @Override
        protected void doClose(final boolean immediately) {
            final AtomicInteger count = new AtomicInteger(1);
            SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
                @Override
                public void operationComplete(CloseFuture f) {
                    if (count.decrementAndGet() == 0) {
                        future.setClosed();
                    }
                }
            };
            for (Closeable c : closeables) {
                if (c != null) {
                    count.incrementAndGet();
                    c.close(immediately).addListener(listener);
                }
            }
            listener.operationComplete(null);
        }
    }

    private static class SequentialCloseable extends SimpleCloseable {

        private final Iterable<? extends Closeable> closeables;

        public SequentialCloseable(Object lock, Iterable<? extends Closeable> closeables) {
            super(lock);
            this.closeables = closeables;
        }

        @Override
        protected void doClose(final boolean immediately) {
            final Iterator<? extends Closeable> iterator = closeables.iterator();
            SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
                @Override
                public void operationComplete(CloseFuture previousFuture) {
                    while (iterator.hasNext()) {
                        Closeable c = iterator.next();
                        if (c != null) {
                            CloseFuture nextFuture = c.close(immediately);
                            nextFuture.addListener(this);
                            return;
                        }
                    }
                    if (!iterator.hasNext()) {
                        future.setClosed();
                    }
                }
            };
            listener.operationComplete(null);
        }
    }

    private static class FuturesCloseable<T extends SshFuture> extends CloseableUtils.SimpleCloseable {

        private final Iterable<? extends SshFuture<T>> futures;

        public FuturesCloseable(Object lock, Iterable<? extends SshFuture<T>> futures) {
            super(lock);
            this.futures = futures;
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
                final AtomicInteger count = new AtomicInteger(1);
                SshFutureListener<T> listener = new SshFutureListener<T>() {
                    @Override
                    public void operationComplete(T f) {
                        if (count.decrementAndGet() == 0) {
                            future.setClosed();
                        }
                    }
                };
                for (SshFuture<T> f : futures) {
                    if (f != null) {
                        count.incrementAndGet();
                        f.addListener(listener);
                    }
                }
                listener.operationComplete(null);
            }
        }
    }

    public static abstract class AbstractCloseable extends IoBaseCloseable {

        protected enum State {
            Opened, Graceful, Immediate, Closed
        }
        /** Lock object for this session state */
        protected final Object lock = new Object();
        /** State of this object */
        protected final AtomicReference<State> state = new AtomicReference<State>(State.Opened);
        /** A future that will be set 'closed' when the object is actually closed */
        protected final CloseFuture closeFuture = new DefaultCloseFuture(lock);

        protected AbstractCloseable() {
            super();
        }

        protected AbstractCloseable(String discriminator) {
            super(discriminator);
        }

        @Override
        public CloseFuture close(boolean immediately) {
            if (immediately) {
                if (state.compareAndSet(State.Opened, State.Immediate)
                        || state.compareAndSet(State.Graceful, State.Immediate)) {
                    log.debug("Closing {} immediately", this);
                    preClose();
                    doCloseImmediately();
                    log.debug("{} closed", this);
                } else {
                    log.debug("{} is already {}", this, state.get() == State.Closed ? "closed" : "closing");
                }
            } else {
                if (state.compareAndSet(State.Opened, State.Graceful)) {
                    log.debug("Closing {} gracefully", this);
                    preClose();
                    SshFuture<CloseFuture> grace = doCloseGracefully();
                    if (grace != null) {
                        grace.addListener(new SshFutureListener<CloseFuture>() {
                            @Override
                            @SuppressWarnings("synthetic-access")
                            public void operationComplete(CloseFuture future) {
                                if (state.compareAndSet(State.Graceful, State.Immediate)) {
                                    doCloseImmediately();
                                    log.debug("{} closed", AbstractCloseable.this);
                                }
                            }
                        });
                    } else {
                        if (state.compareAndSet(State.Graceful, State.Immediate)) {
                            doCloseImmediately();
                            log.debug("{} closed", this);
                        }
                    }
                } else {
                    log.debug("{} is already {}", this, state.get() == State.Closed ? "closed" : "closing");
                }
            }
            return closeFuture;
        }

        @Override
        public boolean isClosed() {
            return state.get() == State.Closed;
        }

        @Override
        public boolean isClosing() {
            return state.get() != State.Opened;
        }

        /**
         * preClose is guaranteed to be called before doCloseGracefully or doCloseImmediately.
         * When preClose() is called, isClosing() == true
         */
        protected void preClose() {
            // nothing
        }

        protected CloseFuture doCloseGracefully() {
            return null;
        }

        /**
         * doCloseImmediately is called once and only once
         * with state == Immediate
         *
         * Overriding methods should always call the base implementation.
         * It may be called concurrently while preClose() or doCloseGracefully is executing
         */
        protected void doCloseImmediately() {
            closeFuture.setClosed();
            state.set(State.Closed);
        }

        @SuppressWarnings("synthetic-access")
        protected Builder builder() {
            return new Builder(lock);
        }

    }

    public static abstract class AbstractInnerCloseable extends AbstractCloseable {

        protected abstract Closeable getInnerCloseable();

        protected AbstractInnerCloseable() {
            super();
        }

        protected AbstractInnerCloseable(String discriminator) {
            super(discriminator);
        }

        @Override
        protected CloseFuture doCloseGracefully() {
            return getInnerCloseable().close(false);
        }

        @Override
        protected void doCloseImmediately() {
            getInnerCloseable().close(true).addListener(new SshFutureListener<CloseFuture>() {
                @Override
                @SuppressWarnings("synthetic-access")
                public void operationComplete(CloseFuture future) {
                    AbstractInnerCloseable.super.doCloseImmediately();
                }
            });
        }
    }
}
