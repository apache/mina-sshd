/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.future;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.StreamCorruptedException;
import java.lang.reflect.Array;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A default implementation of {@link SshFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSshFuture<T extends SshFuture> extends AbstractLoggingBean implements SshFuture<T> {
    /**
     * A default value to indicate the future has been canceled
     */
    private static final Object CANCELED = new Object();
    /**
     * A value indicating a null
     */
    private static final Object NULL = new Object();

    /**
     * A lock used by the wait() method
     */
    private final Object lock;
    private Object listeners;
    private Object result;

    /**
     * Creates a new instance.
     *
     * @param lock A synchronization object for locking access - if {@code null}
     * then synchronization occurs on {@code this} instance
     */
    public DefaultSshFuture(Object lock) {
        this.lock = lock != null ? lock : this;
    }

    @Override
    public T await() throws IOException {
        if (await(Long.MAX_VALUE)) {
            return asT();
        } else {
            throw new SshException("No result while await completion");
        }
    }

    @Override
    public boolean await(long timeout, TimeUnit unit) throws IOException {
        return await(unit.toMillis(timeout));
    }

    @Override
    public boolean await(long timeoutMillis) throws IOException {
        return await0(timeoutMillis, true) != null;
    }

    @Override
    public T awaitUninterruptibly() {
        try {
            await0(Long.MAX_VALUE, false);
        } catch (InterruptedIOException ie) {
            // Do nothing : this catch is just mandatory by contract
        }

        return asT();
    }

    @Override
    public boolean awaitUninterruptibly(long timeout, TimeUnit unit) {
        return awaitUninterruptibly(unit.toMillis(timeout));
    }

    @Override
    public boolean awaitUninterruptibly(long timeoutMillis) {
        try {
            return await0(timeoutMillis, false) != null;
        } catch (InterruptedIOException e) {
            // TODO for JDK-8 use the 2-args constructors
            throw (InternalError) new InternalError("Unexpected interrupted exception wile awaitUninterruptibly "
                    + timeoutMillis + " msec.: " + e.getMessage()).initCause(e);
        }
    }

    /**
     * <P>Waits (interruptible) for the specified timeout (msec.) and then checks
     * the result:</P>
     * <UL>
     * <LI><P>
     * If result is {@code null} then timeout is assumed to have expired - throw
     * an appropriate {@link IOException}
     * </P></LI>
     *
     * <LI><P>
     * If the result is of the expected type, then cast and return it
     * </P></LI>
     *
     * <LI><P>
     * If the result is an {@link IOException} then re-throw it
     * </P></LI>
     *
     * <LI><P>
     * If the result is a {@link Throwable} then throw an {@link IOException}
     * whose cause is the original exception
     * </P></LI>
     *
     * <LI><P>
     * Otherwise (should never happen), throw a {@link StreamCorruptedException}
     * with the name of the result type
     * </P></LI>
     * </UL>
     *
     * @param <R>          The generic result type
     * @param expectedType The expected result type
     * @param timeout      The timeout (millis) to wait for a result
     * @return The (never {@code null}) result
     * @throws IOException If failed to retrieve the expected result on time
     */
    protected <R> R verifyResult(Class<? extends R> expectedType, long timeout) throws IOException {
        Object value = await0(timeout, true);
        if (value == null) {
            throw new SshException("Failed to get operation result within specified timeout: " + timeout);
        }

        Class<?> actualType = value.getClass();
        if (expectedType.isAssignableFrom(actualType)) {
            return expectedType.cast(value);
        } else if (IOException.class.isAssignableFrom(actualType)) {
            throw (IOException) value;
        } else if (Throwable.class.isAssignableFrom(actualType)) {
            Throwable t = (Throwable) value;
            throw new SshException("Failed (" + t.getClass().getSimpleName() + ") to execute: " + t.getMessage(), GenericUtils.resolveExceptionCause(t));
        } else {    // what else can it be ????
            throw new StreamCorruptedException("Unknown result type: " + actualType.getName());
        }
    }

    /**
     * Wait for the Future to be ready. If the requested delay is 0 or
     * negative, this method immediately returns.
     *
     * @param timeoutMillis The delay we will wait for the Future to be ready
     * @param interruptable Tells if the wait can be interrupted or not.
     *                      If {@code true} and the thread is interrupted then an {@link InterruptedIOException}
     *                      is thrown.
     * @return The non-{@code null} result object if the Future is ready,
     * {@code null} if the timeout expired and no result was received
     * @throws InterruptedIOException If the thread has been interrupted
     *                                when it's not allowed.
     */
    protected Object await0(long timeoutMillis, boolean interruptable) throws InterruptedIOException {
        ValidateUtils.checkTrue(timeoutMillis >= 0L, "Negative timeout N/A: %d", timeoutMillis);
        long startTime = System.currentTimeMillis();
        long curTime = startTime;
        long endTime = ((Long.MAX_VALUE - timeoutMillis) < curTime) ? Long.MAX_VALUE : (curTime + timeoutMillis);

        synchronized (lock) {
            if ((result != null) || (timeoutMillis <= 0)) {
                return result;
            }

            for (;;) {
                try {
                    lock.wait(endTime - curTime);
                } catch (InterruptedException e) {
                    if (interruptable) {
                        curTime = System.currentTimeMillis();
                        throw (InterruptedIOException) new InterruptedIOException("Interrupted after " + (curTime - startTime) + " msec.").initCause(e);
                    }
                }

                curTime = System.currentTimeMillis();
                if ((result != null) || (curTime >= endTime)) {
                    return result;
                }
            }
        }
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

            result = newValue != null ? newValue : NULL;
            lock.notifyAll();
        }

        notifyListeners();
    }

    /**
     * @return The result of the asynchronous operation.
     */
    protected Object getValue() {
        synchronized (lock) {
            return result == NULL ? null : result;
        }
    }

    @Override
    public T addListener(SshFutureListener<T> listener) {
        ValidateUtils.checkNotNull(listener, "Missing listener argument");
        boolean notifyNow = false;
        synchronized (lock) {
            if (result != null) {
                notifyNow = true;
            } else {
                if (listeners == null) {
                    listeners = listener;
                } else if (listeners instanceof SshFutureListener) {
                    listeners = new Object[]{listeners, listener};
                } else {
                    Object[] ol = (Object[]) listeners;
                    int l = ol.length;
                    Object[] nl = new Object[l + 1];
                    System.arraycopy(ol, 0, nl, 0, l);
                    nl[l] = listener;
                    listeners = nl;
                }
            }
        }

        if (notifyNow) {
            notifyListener(listener);
        }
        return asT();
    }

    @Override
    public T removeListener(SshFutureListener<T> listener) {
        ValidateUtils.checkNotNull(listener, "No listener provided");

        synchronized (lock) {
            if (result == null) {
                if (listeners != null) {
                    if (listeners == listener) {
                        listeners = null;
                    } else {
                        int l = Array.getLength(listeners);
                        for (int i = 0; i < l; i++) {
                            if (Array.get(listeners, i) == listener) {
                                Array.set(listeners, i, null);
                                break;
                            }
                        }
                    }
                }
            }
        }

        return asT();
    }

    private void notifyListeners() {
        // There won't be any visibility problem or concurrent modification
        // because 'ready' flag will be checked against both addListener and
        // removeListener calls.
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

    private void notifyListener(SshFutureListener<T> l) {
        try {
            l.operationComplete(asT());
        } catch (Throwable t) {
            log.warn("Listener threw an exception", t);
        }
    }

    public boolean isCanceled() {
        return getValue() == CANCELED;
    }

    public void cancel() {
        setValue(CANCELED);
    }

    @SuppressWarnings("unchecked")
    private SshFutureListener<T> asListener(Object o) {
        return (SshFutureListener<T>) o;
    }

    @SuppressWarnings("unchecked")
    private T asT() {
        return (T) this;
    }
}
