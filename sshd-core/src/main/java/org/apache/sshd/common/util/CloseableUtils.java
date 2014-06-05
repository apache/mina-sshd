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

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class to help with {@link Closeable}s.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CloseableUtils {

    public static CloseFuture closed() {
        CloseFuture future = new DefaultCloseFuture(null);
        future.setClosed();
        return future;
    }

    public static Closeable parallel(final Collection<? extends Closeable> closeables) {
        return parallel(null, closeables);
    }

    public static Closeable parallel(final Object lock, final Collection<? extends Closeable> closeables) {
        return parallel(lock, closeables.toArray(new Closeable[closeables.size()]));
    }

    public static Closeable parallel(final Closeable... closeables) {
        return parallel(null, closeables);
    }

    public static Closeable parallel(final Object lock, final Closeable... closeables) {
        int nbNonNulls = 0;
        for (Closeable closeable : closeables) {
            if (closeable != null) {
                nbNonNulls++;
            }
        }
        if (nbNonNulls == 0) {
            return new Closeable() {
                final CloseFuture future = new DefaultCloseFuture(lock);
                public boolean isClosed() {
                    return future.isClosed();
                }
                public boolean isClosing() {
                    return isClosed();
                }
                public CloseFuture close(boolean immediately) {
                    future.setClosed();
                    return future;
                }
            };
        } else if (nbNonNulls == 1) {
            for (Closeable closeable : closeables) {
                if (closeable != null) {
                    return closeable;
                }
            }
            throw new IllegalStateException();
        } else {
            return new Closeable() {
                final CloseFuture future = new DefaultCloseFuture(lock);
                final AtomicBoolean closing = new AtomicBoolean();
                public boolean isClosed() {
                    return future.isClosed();
                }
                public boolean isClosing() {
                    return closing.get();
                }
                public CloseFuture close(boolean immediately) {
                    final AtomicInteger count = new AtomicInteger(closeables.length);
                    if (closing.compareAndSet(false, true)) {
                        SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
                            public void operationComplete(CloseFuture f) {
                                if (count.decrementAndGet() == 0) {
                                    future.setClosed();
                                }
                            }
                        };
                        for (Closeable c : closeables) {
                            if (c != null) {
                                c.close(immediately).addListener(listener);
                            } else {
                                listener.operationComplete(null);
                            }
                        }
                    }
                    return future;
                }
            };
        }
    }

    public static Closeable sequential(final Collection<? extends Closeable> closeables) {
        return sequential(null, closeables);
    }

    public static Closeable sequential(final Object lock, final Collection<? extends Closeable> closeables) {
        return sequential(lock, closeables.toArray(new Closeable[closeables.size()]));
    }

    public static Closeable sequential(final Closeable... closeables) {
        return sequential(null, closeables);
    }

    public static Closeable sequential(final Object lock, final Closeable... closeables) {
        int nbNonNulls = 0;
        for (Closeable closeable : closeables) {
            if (closeable != null) {
                nbNonNulls++;
            }
        }
        if (nbNonNulls == 0) {
            return new Closeable() {
                final CloseFuture future = new DefaultCloseFuture(lock);
                public boolean isClosed() {
                    return future.isClosed();
                }
                public boolean isClosing() {
                    return isClosed();
                }
                public CloseFuture close(boolean immediately) {
                    future.setClosed();
                    return future;
                }
            };
        } else if (nbNonNulls == 1) {
            for (Closeable closeable : closeables) {
                if (closeable != null) {
                    return closeable;
                }
            }
            throw new IllegalStateException();
        } else {
            return new Closeable() {
                final DefaultCloseFuture future = new DefaultCloseFuture(lock);
                final AtomicBoolean closing = new AtomicBoolean();
                public boolean isClosed() {
                    return future.isClosed();
                }
                public boolean isClosing() {
                    return closing.get();
                }
                public CloseFuture close(final boolean immediately) {
                    if (closing.compareAndSet(false, true)) {
                        final Iterator<Closeable> iterator = Arrays.asList(closeables).iterator();
                        SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
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
                    return future;
                }
            };
        }
    }

    public static <T extends SshFuture> CloseFuture parallel(final SshFuture<T>... futures) {
        return parallel(null, futures);
    }

    public static <T extends SshFuture> CloseFuture parallel(Object lock, final SshFuture<T>... futures) {
        final CloseFuture future = new DefaultCloseFuture(lock);
        if (futures.length > 0) {
            final AtomicInteger count = new AtomicInteger(futures.length);
            SshFutureListener<T> listener = new SshFutureListener<T>() {
                public void operationComplete(T f) {
                    if (count.decrementAndGet() == 0) {
                        future.setClosed();
                    }
                }
            };
            for (SshFuture<T> f : futures) {
                if (f != null) {
                    f.addListener(listener);
                } else {
                    listener.operationComplete(null);
                }
            }
        } else {
            future.setClosed();
        }
        return future;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(Logger logger, Object lock) {
        return new Builder();
    }

    public static class Builder {
        private final Object lock;
        private Closeable closeable = null;
        public Builder() {
            this(null);
        }
        public Builder(Object lock) {
            this.lock = lock;
        }
        public <T extends SshFuture> Builder when(final SshFuture<T>... futures) {
            return close(new Closeable() {
                private volatile boolean closing;
                private volatile boolean closed;
                public CloseFuture close(boolean immediately) {
                    closing = true;
                    if (immediately) {
                        for (SshFuture<?> future : futures) {
                            if (future instanceof DefaultSshFuture) {
                                ((DefaultSshFuture<?>) future).setValue(new SshException("Closed"));
                            }
                        }
                        closed = true;
                        return closed();
                    } else {
                        return CloseableUtils.parallel(lock, futures).addListener(new SshFutureListener<CloseFuture>() {
                            public void operationComplete(CloseFuture future) {
                                closed = true;
                            }
                        });
                    }
                }

                public boolean isClosed() {
                    return closed;
                }

                public boolean isClosing() {
                    return closing || closed;
                }
            });
        }
        public <T extends SshFuture> Builder when(Collection<? extends SshFuture<T>> futures) {
            return when(futures.toArray(new SshFuture[futures.size()]));
        }
        public Builder sequential(Closeable... closeables) {
            return close(CloseableUtils.sequential(lock, closeables));
        }
        public Builder sequential(Collection<Closeable> closeables) {
            return close(CloseableUtils.sequential(lock, closeables));
        }
        public Builder parallel(Closeable... closeables) {
            return close(CloseableUtils.parallel(lock, closeables));
        }
        public Builder parallel(Collection<? extends Closeable> closeables) {
            return close(CloseableUtils.parallel(lock, closeables));
        }
        public Builder close(Closeable c) {
            if (closeable == null) {
                closeable = c;
            } else {
                closeable = CloseableUtils.sequential(lock, closeable, c);
            }
            return this;
        }
        public Closeable build() {
            if (closeable == null) {
                closeable = new Closeable() {
                    private volatile boolean closed;
                    public CloseFuture close(boolean immediately) {
                        closed = true;
                        return closed();
                    }
                    public boolean isClosed() {
                        return closed;
                    }
                    public boolean isClosing() {
                        return closed;
                    }
                };
            }
            return closeable;
        }
    }

    public static abstract class AbstractCloseable implements Closeable {

        protected static final int OPENED = 0;
        protected static final int GRACEFUL = 1;
        protected static final int IMMEDIATE = 2;
        protected static final int CLOSED = 3;

        /** Our logger */
        protected final Logger log = LoggerFactory.getLogger(getClass());
        /** Lock object for this session state */
        protected final Object lock;
        /** State of this object */
        protected final AtomicInteger state = new AtomicInteger(OPENED);
        /** A future that will be set 'closed' when the object is actually closed */
        protected final CloseFuture closeFuture;

        protected AbstractCloseable() {
            this(new Object());
        }

        protected AbstractCloseable(Object lock) {
            this.lock = lock;
            this.closeFuture = new DefaultCloseFuture(lock);
        }

        public CloseFuture close(boolean immediately) {
            if (immediately) {
                if (state.compareAndSet(OPENED, IMMEDIATE) || state.compareAndSet(GRACEFUL, IMMEDIATE)) {
                    log.debug("Closing {} immediately", this);
                    preClose();
                    doCloseImmediately();
                    log.debug("{} closed", this);
                } else {
                    log.debug("{} is already {}", this, state.get() == CLOSED ? "closed" : "closing");
                }
            } else {
                if (state.compareAndSet(OPENED, GRACEFUL)) {
                    log.debug("Closing {} gracefully", this);
                    preClose();
                    SshFuture<CloseFuture> grace = doCloseGracefully();
                    if (grace != null) {
                        grace.addListener(new SshFutureListener<CloseFuture>() {
                            public void operationComplete(CloseFuture future) {
                                if (state.compareAndSet(GRACEFUL, IMMEDIATE)) {
                                    doCloseImmediately();
                                    log.debug("{} closed", AbstractCloseable.this);
                                }
                            }
                        });
                    } else {
                        if (state.compareAndSet(GRACEFUL, IMMEDIATE)) {
                            doCloseImmediately();
                            log.debug("{} closed", this);
                        }
                    }
                } else {
                    log.debug("{} is already {}", this, state.get() == CLOSED ? "closed" : "closing");
                }
            }
            return closeFuture;
        }

        public boolean isClosed() {
            return state.get() == CLOSED;
        }

        public boolean isClosing() {
            return state.get() != OPENED;
        }

        protected void preClose() {
        }

        protected CloseFuture doCloseGracefully() {
            return null;
        }

        protected void doCloseImmediately() {
            closeFuture.setClosed();
            state.set(CLOSED);
        }

        protected Builder builder() {
            return new Builder(lock);
        }

    }

    public static abstract class AbstractInnerCloseable extends AbstractCloseable {

        protected abstract Closeable getInnerCloseable();

        @Override
        protected CloseFuture doCloseGracefully() {
            return getInnerCloseable().close(false);
        }

        @Override
        protected void doCloseImmediately() {
            getInnerCloseable().close(true).addListener(new SshFutureListener<CloseFuture>() {
                public void operationComplete(CloseFuture future) {
                    AbstractInnerCloseable.super.doCloseImmediately();
                }
            });
        }
    }

    private CloseableUtils() {
    }
}
