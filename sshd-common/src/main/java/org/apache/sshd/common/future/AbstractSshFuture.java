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
import java.util.function.Function;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @param  <T> Type of future
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSshFuture<T extends SshFuture> extends AbstractLoggingBean implements SshFuture<T> {
    /**
     * A default value to indicate the future has been canceled
     */
    protected static final Object CANCELED = new Object();

    private final Object id;

    /**
     * @param id Some identifier useful as {@code toString()} value
     */
    protected AbstractSshFuture(Object id) {
        this.id = id;
    }

    @Override
    public Object getId() {
        return id;
    }

    @Override
    public boolean await(long timeoutMillis) throws IOException {
        return await0(timeoutMillis, true) != null;
    }

    @Override
    public boolean awaitUninterruptibly(long timeoutMillis) {
        try {
            return await0(timeoutMillis, false) != null;
        } catch (InterruptedIOException e) {
            throw formatExceptionMessage(
                    msg -> new InternalError(msg, e),
                    "Unexpected interrupted exception wile awaitUninterruptibly %d msec: %s",
                    timeoutMillis, e.getMessage());
        }
    }

    /**
     * <P>
     * Waits (interruptible) for the specified timeout (msec.) and then checks the result:
     * </P>
     * <UL>
     * <LI>
     * <P>
     * If result is {@code null} then timeout is assumed to have expired - throw an appropriate {@link IOException}
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * If the result is of the expected type, then cast and return it
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * If the result is a {@link Throwable} then throw an {@link IOException} whose cause is the original exception
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * Otherwise (should never happen), throw a {@link StreamCorruptedException} with the name of the result type
     * </P>
     * </LI>
     * </UL>
     *
     * @param  <R>          The generic result type
     * @param  expectedType The expected result type
     * @param  timeout      The timeout (millis) to wait for a result
     * @return              The (never {@code null}) result
     * @throws IOException  If failed to retrieve the expected result on time
     */
    protected <R> R verifyResult(Class<? extends R> expectedType, long timeout) throws IOException {
        Object value = await0(timeout, true);
        if (value == null) {
            throw formatExceptionMessage(
                    SshException::new,
                    "Failed to get operation result within specified timeout: %s",
                    timeout);
        }

        Class<?> actualType = value.getClass();
        if (expectedType.isAssignableFrom(actualType)) {
            return expectedType.cast(value);
        }

        if (Throwable.class.isAssignableFrom(actualType)) {
            Throwable t = GenericUtils.peelException((Throwable) value);

            if (t instanceof SshException) {
                throw new SshException(((SshException) t).getDisconnectCode(), t.getMessage(), t);
            }

            Throwable cause = GenericUtils.resolveExceptionCause(t);
            throw formatExceptionMessage(
                    msg -> new SshException(msg, cause),
                    "Failed (%s) to execute: %s",
                    t.getClass().getSimpleName(), t.getMessage());
        } else { // what else can it be ????
            throw formatExceptionMessage(
                    StreamCorruptedException::new, "Unknown result type: %s", actualType.getName());
        }
    }

    /**
     * Wait for the Future to be ready. If the requested delay is 0 or negative, this method returns immediately.
     *
     * @param  timeoutMillis          The delay we will wait for the Future to be ready
     * @param  interruptable          Tells if the wait can be interrupted or not. If {@code true} and the thread is
     *                                interrupted then an {@link InterruptedIOException} is thrown.
     * @return                        The non-{@code null} result object if the Future is ready, {@code null} if the
     *                                timeout expired and no result was received
     * @throws InterruptedIOException If the thread has been interrupted when it's not allowed.
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
            warn("notifyListener({}) failed ({}) to invoke {}: {}",
                    this, t.getClass().getSimpleName(), l, t.getMessage(), t);
        }
    }

    @SuppressWarnings("unchecked")
    protected T asT() {
        return (T) this;
    }

    /**
     * Generates an exception whose message is prefixed by the future simple class name + {@link #getId() identifier} as
     * a hint to the context of the failure.
     *
     * @param  <E>              Type of {@link Throwable} being generated
     * @param  exceptionCreator The exception creator from the formatted message
     * @param  format           The extra payload format as per {@link String#format(String, Object...)}
     * @param  args             The formatting arguments
     * @return                  The generated exception
     */
    protected <E extends Throwable> E formatExceptionMessage(
            Function<? super String, ? extends E> exceptionCreator, String format, Object... args) {
        String messagePayload = String.format(format, args);
        String excMessage = getClass().getSimpleName() + "[" + getId() + "]: " + messagePayload;
        return exceptionCreator.apply(excMessage);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[id=" + getId() + "]";
    }
}
