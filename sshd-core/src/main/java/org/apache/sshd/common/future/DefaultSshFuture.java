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
package org.apache.sshd.common.future;

import java.lang.reflect.Array;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A default implementation of {@link SshFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSshFuture<T extends SshFuture> implements SshFuture<T> {

    final Logger logger = LoggerFactory.getLogger(getClass());

    /** A default value to indicate the future has been canceled */
    private static final Object CANCELED = new Object();
    /** A value indicating a null */
    private static final Object NULL = new Object();

    /** A lock used by the wait() method */
    private final Object lock;
    private Object listeners;
    private Object result;

    /**
     * Creates a new instance.
     */
    public DefaultSshFuture(Object lock) {
        this.lock = lock != null ? lock : this;
    }

    /**
     * {@inheritDoc}
     */
    public T await() throws InterruptedException {
        synchronized (lock) {
            while (result == null) {
                lock.wait();
            }
        }
        return asT();
    }

    /**
     * {@inheritDoc}
     */
    public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
        return await(unit.toMillis(timeout));
    }

    /**
     * {@inheritDoc}
     */
    public boolean await(long timeoutMillis) throws InterruptedException {
        return await0(timeoutMillis, true);
    }

    /**
     * {@inheritDoc}
     */
    public T awaitUninterruptibly() {
        try {
            await0(Long.MAX_VALUE, false);
        } catch ( InterruptedException ie) {
            // Do nothing : this catch is just mandatory by contract
        }

        return asT();
    }

    /**
     * {@inheritDoc}
     */
    public boolean awaitUninterruptibly(long timeout, TimeUnit unit) {
        return awaitUninterruptibly(unit.toMillis(timeout));
    }

    /**
     * {@inheritDoc}
     */
    public boolean awaitUninterruptibly(long timeoutMillis) {
        try {
            return await0(timeoutMillis, false);
        } catch (InterruptedException e) {
            throw new InternalError();
        }
    }

    /**
     * Wait for the Future to be ready. If the requested delay is 0 or
     * negative, this method immediately returns the value of the
     * 'ready' flag.
     * Every 5 second, the wait will be suspended to be able to check if
     * there is a deadlock or not.
     *
     * @param timeoutMillis The delay we will wait for the Future to be ready
     * @param interruptable Tells if the wait can be interrupted or not
     * @return <code>true</code> if the Future is ready
     * @throws InterruptedException If the thread has been interrupted
     * when it's not allowed.
     */
    private boolean await0(long timeoutMillis, boolean interruptable) throws InterruptedException {
        long curTime = System.currentTimeMillis();
        long endTime = Long.MAX_VALUE - timeoutMillis < curTime ? Long.MAX_VALUE : curTime + timeoutMillis;

        synchronized (lock) {
            if (result != null || timeoutMillis <= 0) {
                return result != null;
            }

            for (;;) {
                try {
                    lock.wait(endTime - curTime);
                } catch (InterruptedException e) {
                    if (interruptable) {
                        throw e;
                    }
                }

                curTime = System.currentTimeMillis();
                if (result != null || curTime >= endTime) {
                    return result != null;
                }
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean isDone() {
        synchronized (lock) {
            return result != null;
        }
    }

    /**
     * Sets the result of the asynchronous operation, and mark it as finished.
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
     * Returns the result of the asynchronous operation.
     */
    protected Object getValue() {
        synchronized (lock) {
            return result == NULL ? null : result;
        }
    }

    /**
     * {@inheritDoc}
     */
    public T addListener(SshFutureListener<T> listener) {
        if (listener == null) {
            throw new NullPointerException("listener");
        }

        boolean notifyNow = false;
        synchronized (lock) {
            if (result != null) {
                notifyNow = true;
            } else {
                if (listeners == null) {
                    listeners = listener;
                } else if (listeners instanceof SshFutureListener) {
                    listeners = new Object[] { listeners, listener };
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

    /**
     * {@inheritDoc}
     */
    public T removeListener(SshFutureListener<T> listener) {
        if (listener == null) {
            throw new NullPointerException("listener");
        }

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
            logger.warn("Listener threw an exception", t);
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
