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

import java.io.InterruptedIOException;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeoutException;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A default implementation of {@link SshFuture}.
 *
 * @param  <T> Type of future
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSshFuture<T extends SshFuture<T>> extends AbstractSshFuture<T> {
    /**
     * A lock used by the wait() method
     */
    private final Object lock;
    private Object listeners;
    private Object result;

    /**
     * Creates a new instance.
     *
     * @param id   Some identifier useful as {@code toString()} value
     * @param lock A synchronization object for locking access - if {@code null} then synchronization occurs on
     *             {@code this} instance
     */
    public DefaultSshFuture(Object id, Object lock) {
        super(id);

        this.lock = (lock != null) ? lock : this;
    }

    @Override
    protected Object await0(long timeoutMillis, boolean interruptable, CancelOption... options)
            throws InterruptedIOException {
        ValidateUtils.checkTrue(timeoutMillis >= 0L, "Negative timeout N/A: %d", timeoutMillis);
        long startTime = System.currentTimeMillis();
        long curTime = startTime;
        long endTime = ((Long.MAX_VALUE - timeoutMillis) < curTime) ? Long.MAX_VALUE : (curTime + timeoutMillis);

        boolean canceled = false;
        try {
            synchronized (lock) {
                if (result != null) {
                    return result;
                }
                if (timeoutMillis <= 0) {
                    result = cancelOnTimeout(timeoutMillis, options);
                    canceled = result != null;
                    return null;
                }

                for (;;) {
                    try {
                        lock.wait(endTime - curTime);
                    } catch (InterruptedException e) {
                        if (interruptable) {
                            curTime = System.currentTimeMillis();
                            InterruptedIOException interrupted = formatExceptionMessage(msg -> {
                                InterruptedIOException exc = new InterruptedIOException(msg);
                                exc.initCause(e);
                                return exc;
                            }, "Interrupted after %d msec.", curTime - startTime);
                            if (result == null && Arrays.asList(options).contains(CancelOption.CANCEL_ON_INTERRUPT)) {
                                CancelFuture future = createCancellation();
                                if (future != null) {
                                    CancellationException cancellation = new CancellationException("Canceled on interrupt");
                                    cancellation.initCause(interrupted);
                                    future.setBackTrace(cancellation);
                                    result = future;
                                    canceled = true;
                                }
                            }
                            throw interrupted;
                        }
                    }

                    if (result != null) {
                        return result;
                    }
                    curTime = System.currentTimeMillis();
                    if (curTime >= endTime) {
                        result = cancelOnTimeout(timeoutMillis, options);
                        canceled = result != null;
                        return null;
                    }
                }
            }
        } finally {
            // Notify listeners outside the monitor
            if (canceled) {
                notifyListeners();
            }
        }
    }

    private CancelFuture cancelOnTimeout(long timeoutMillis, CancelOption... options) {
        if (Arrays.asList(options).contains(CancelOption.CANCEL_ON_TIMEOUT)) {
            CancelFuture future = createCancellation();
            if (future != null) {
                TimeoutException cause = new TimeoutException("Timed out after " + timeoutMillis + "msec");
                CancellationException cancellation = new CancellationException(cause.getMessage());
                cancellation.initCause(cause);
                future.setBackTrace(cancellation);
                return future;
            }
        }
        return null;
    }

    @Override
    public boolean isDone() {
        synchronized (lock) {
            return result != null;
        }
    }

    /**
     * Sets the result of the asynchronous operation, and mark it as finished.
     *
     * @param newValue The operation result
     */
    public void setValue(Object newValue) {
        synchronized (lock) {
            // Allow only once.
            if (result != null) {
                return;
            }

            result = (newValue != null) ? newValue : GenericUtils.NULL;
            onValueSet(newValue);
            lock.notifyAll();
        }

        notifyListeners();
    }

    public int getNumRegisteredListeners() {
        synchronized (lock) {
            if (listeners == null) {
                return 0;
            } else if (listeners instanceof SshFutureListener) {
                return 1;
            } else {
                int l = Array.getLength(listeners);
                int count = 0;
                for (int i = 0; i < l; i++) {
                    if (Array.get(listeners, i) != null) {
                        count++;
                    }
                }
                return count;
            }
        }
    }

    /**
     * @return The result of the asynchronous operation - or {@code null} if none set.
     */
    public Object getValue() {
        synchronized (lock) {
            return (result == GenericUtils.NULL) ? null : result;
        }
    }

    @Override
    public T addListener(SshFutureListener<T> listener) {
        Objects.requireNonNull(listener, "Missing listener argument");
        boolean notifyNow = false;
        synchronized (lock) {
            // if already have a result don't register the listener and invoke it directly
            if (result != null) {
                notifyNow = true;
            } else if (listeners == null) {
                listeners = listener; // 1st listener ?
            } else if (listeners instanceof SshFutureListener) {
                listeners = new Object[] { listeners, listener };
            } else { // increase array of registered listeners
                Object[] ol = (Object[]) listeners;
                int l = ol.length;
                Object[] nl = new Object[l + 1];
                System.arraycopy(ol, 0, nl, 0, l);
                nl[l] = listener;
                listeners = nl;
            }
        }

        if (notifyNow) {
            notifyListener(listener);
        }

        return asT();
    }

    @Override
    public T removeListener(SshFutureListener<T> listener) {
        Objects.requireNonNull(listener, "No listener provided");

        synchronized (lock) {
            if (result != null) {
                return asT(); // the train has already left the station...
            }

            if (listeners == null) {
                return asT(); // no registered instances anyway
            }

            if (listeners == listener) {
                listeners = null; // the one and only
            } else if (!(listeners instanceof SshFutureListener)) {
                int l = Array.getLength(listeners);
                for (int i = 0; i < l; i++) {
                    if (Array.get(listeners, i) == listener) {
                        Array.set(listeners, i, null);
                        break;
                    }
                }
            }
        }

        return asT();
    }

    protected void notifyListeners() {
        /*
         * There won't be any visibility problem or concurrent modification because result value is checked in both
         * addListener and removeListener calls under lock. If the result is already set then both methods will not
         * modify the internal listeners
         */
        if (listeners != null) {
            if (listeners instanceof SshFutureListener) {
                notifyListener(asListener(listeners));
            } else {
                int l = Array.getLength(listeners);
                for (int i = 0; i < l; i++) {
                    SshFutureListener<T> listener = asListener(Array.get(listeners, i));
                    if (listener != null) {
                        notifyListener(listener);
                    }
                }
            }
        }
    }

    /**
     * Creates a {@link CancelFuture} if this future can be canceled.
     * <p>
     * This doesn't cancel this future yet.
     * </p>
     *
     * @return A {@link CancelFuture} that can be used to wait for the cancellation to have been effected, or
     *         {@code null} if the future cannot be canceled.
     */
    protected CancelFuture createCancellation() {
        return null;
    }

    /**
     * Callback that is invoked under lock when the future's value is set.
     * <p>
     * As this is called under lock, subclasses should not do any elaborate processing. It is intended to give
     * subclasses a safe and convenient way to update local state before any listeners are invoked or callers waiting in
     * {@link #await0(long, boolean, CancelOption...)} are woken up.
     * </p>
     * <p>
     * The default implementation does nothing.
     * </p>
     *
     * @param value that was just set
     */
    protected void onValueSet(Object value) {
        // Do nothing
    }

    @Override
    public String toString() {
        return super.toString() + "[value=" + result + "]";
    }
}
