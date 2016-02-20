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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.StreamCorruptedException;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @param <T> Type of future
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSshFuture<T extends SshFuture> extends AbstractLoggingBean implements SshFuture<T> {
    /**
     * A default value to indicate the future has been canceled
     */
    protected static final Object CANCELED = new Object();

    protected AbstractSshFuture() {
        super();
    }

    @Override   // TODO make this a default method in JDK-8
    public boolean await() throws IOException {
        return await(Long.MAX_VALUE);
    }

    @Override   // TODO make this a default method in JDK-8
    public boolean await(long timeout, TimeUnit unit) throws IOException {
        return await(unit.toMillis(timeout));
    }

    @Override
    public boolean await(long timeoutMillis) throws IOException {
        return await0(timeoutMillis, true) != null;
    }

    @Override   // TODO make this a default method in JDK-8
    public boolean awaitUninterruptibly() {
        return awaitUninterruptibly(Long.MAX_VALUE);
    }

    @Override   // TODO make this a default method in JDK-8
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
        }

        if (Throwable.class.isAssignableFrom(actualType)) {
            Throwable t = GenericUtils.peelException((Throwable) value);
            if (t != value) {
                value = t;
                actualType = value.getClass();
            }

            if (IOException.class.isAssignableFrom(actualType)) {
                throw (IOException) value;
            }

            throw new SshException("Failed (" + t.getClass().getSimpleName() + ") to execute: " + t.getMessage(), GenericUtils.resolveExceptionCause(t));
        } else {    // what else can it be ????
            throw new StreamCorruptedException("Unknown result type: " + actualType.getName());
        }
    }

    /**
     * Wait for the Future to be ready. If the requested delay is 0 or
     * negative, this method returns immediately.
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
    protected abstract Object await0(long timeoutMillis, boolean interruptable) throws InterruptedIOException;

    @SuppressWarnings("unchecked")
    protected SshFutureListener<T> asListener(Object o) {
        return (SshFutureListener<T>) o;
    }

    protected void notifyListener(SshFutureListener<T> l) {
        try {
            l.operationComplete(asT());
        } catch (Throwable t) {
            log.warn("notifyListener({}) failed ({}) to invoke {}: {}",
                     this, t.getClass().getSimpleName(), l, t.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("notifyListener(" + this + ")[" + l + "] invocation failure details", t);
            }
        }
    }

    @SuppressWarnings("unchecked")
    protected T asT() {
        return (T) this;
    }
}
