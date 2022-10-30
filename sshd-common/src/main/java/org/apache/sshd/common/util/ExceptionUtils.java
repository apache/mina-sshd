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

package org.apache.sshd.common.util;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.concurrent.ExecutionException;

import javax.management.MBeanException;
import javax.management.ReflectionException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class ExceptionUtils {
    private ExceptionUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static void rethrowAsIoException(Throwable e) throws IOException {
        if (e instanceof IOException) {
            throw (IOException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else if (e instanceof Error) {
            throw (Error) e;
        } else {
            throw new IOException(e);
        }
    }

    /**
     * Used to &quot;accumulate&quot; exceptions of the <U>same type</U>. If the current exception is {@code null} then
     * the new one becomes the current, otherwise the new one is added as a <U>suppressed</U> exception to the current
     * one
     *
     * @param  <T>     The exception type
     * @param  current The current exception
     * @param  extra   The extra/new exception
     * @return         The resolved exception
     * @see            Throwable#addSuppressed(Throwable)
     */
    public static <T extends Throwable> T accumulateException(T current, T extra) {
        if (current == null) {
            return extra;
        }

        if ((extra == null) || (extra == current)) {
            return current;
        }

        current.addSuppressed(extra);
        return current;
    }

    /**
     * @param  t The original {@link Throwable} - ignored if {@code null}
     * @return   If {@link Throwable#getCause()} is non-{@code null} then the cause, otherwise the original exception -
     *           {@code null} if the original exception was {@code null}
     */
    public static Throwable resolveExceptionCause(Throwable t) {
        if (t == null) {
            return t;
        }

        Throwable c = t.getCause();
        if (c == null) {
            return t;
        } else {
            return c;
        }
    }

    /**
     * Attempts to get to the &quot;effective&quot; exception being thrown, by taking care of some known exceptions that
     * wrap the original thrown one.
     *
     * @param  t The original {@link Throwable} - ignored if {@code null}
     * @return   The effective exception - same as input if not a wrapper
     */
    public static Throwable peelException(Throwable t) {
        // NOTE: check order is important - e.g., InvocationTargetException extends ReflectiveOperationException
        if (t == null) {
            return t;
        } else if (t instanceof UndeclaredThrowableException) {
            Throwable wrapped = ((UndeclaredThrowableException) t).getUndeclaredThrowable();
            // according to the Javadoc it may be null, in which case 'getCause'
            // might contain the information we need
            if (wrapped != null) {
                return peelException(wrapped);
            }

            wrapped = t.getCause();
            if (wrapped != t) { // make sure it is a real cause
                return peelException(wrapped);
            }
        } else if (t instanceof InvocationTargetException) {
            Throwable target = ((InvocationTargetException) t).getTargetException();
            if (target != null) {
                return peelException(target);
            }
        } else if (t instanceof ReflectionException) {
            Throwable target = ((ReflectionException) t).getTargetException();
            if (target != null) {
                return peelException(target);
            }
        } else if (t instanceof ExecutionException) {
            return peelException(resolveExceptionCause(t));
        } else if (t instanceof MBeanException) {
            Throwable target = ((MBeanException) t).getTargetException();
            if (target != null) {
                return peelException(target);
            }
        }

        return t; // no special handling required or available
    }

    /**
     * Converts a thrown generic exception to a {@link RuntimeException}
     *
     * @param  t             The original thrown exception
     * @param  peelThrowable Whether to determine the root cause by &quot;peeling&quot; any enclosing exceptions
     * @return               The thrown cause if already a runtime exception, otherwise a runtime exception of the
     *                       resolved exception as its cause
     * @see                  #peelException(Throwable)
     */
    public static RuntimeException toRuntimeException(Throwable t, boolean peelThrowable) {
        Throwable e = peelThrowable ? peelException(t) : t;
        if (e instanceof RuntimeException) {
            return (RuntimeException) e;
        }

        return new RuntimeException(e);
    }

    public static RuntimeException toRuntimeException(Throwable t) {
        return toRuntimeException(t, true);
    }

}
