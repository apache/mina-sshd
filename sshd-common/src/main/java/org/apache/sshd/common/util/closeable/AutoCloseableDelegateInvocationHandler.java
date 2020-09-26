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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ProxyUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps a target instance and an {@link AutoCloseable} delegate into a proxy instance that closes both when wrapper
 * {@link AutoCloseable#close() close} method called.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AutoCloseableDelegateInvocationHandler implements InvocationHandler {
    private final Object proxyTarget;
    private final AutoCloseable delegate;
    // Order is important - we want to close the proxy before the delegate
    private final Object[] closers;

    public AutoCloseableDelegateInvocationHandler(Object proxyTarget, AutoCloseable delegate) {
        this.proxyTarget = Objects.requireNonNull(proxyTarget, "No proxy target to wrap");
        this.delegate = Objects.requireNonNull(delegate, "No delegate to auto-close");
        this.closers = new Object[] { proxyTarget, delegate };
    }

    public Object getProxyTarget() {
        return proxyTarget;
    }

    public AutoCloseable getAutoCloseableDelegate() {
        return delegate;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        // If not invoking "close" then propagate to target as-is
        if (!isCloseMethodInvocation(method, args)) {
            Object target = getProxyTarget();
            try {
                return method.invoke(target, args);
            } catch (Throwable t) {
                Class<?> targetType = target.getClass();
                Logger log = LoggerFactory.getLogger(targetType);
                LoggingUtils.debug(log, "invoke({}#{}) failed ({}) to execute: {}",
                        targetType.getSimpleName(), method.getName(), t.getClass().getSimpleName(), t.getMessage(), t);
                throw ProxyUtils.unwrapInvocationThrowable(t);
            }
        }

        Throwable err = null;
        for (Object c : closers) {
            if (!(c instanceof AutoCloseable)) {
                continue;   // OK if proxy target is not AutoCloseable
            }

            try {
                method.invoke(c, args);
            } catch (Throwable t) {
                Class<? extends Object> closerType = c.getClass();
                Logger log = LoggerFactory.getLogger(closerType);
                LoggingUtils.debug(log, "invoke({}#{}) failed ({}) to execute: {}",
                        closerType.getSimpleName(), method.getName(), t.getClass().getSimpleName(), t.getMessage(), t);
                err = GenericUtils.accumulateException(err, t);
            }
        }

        if (err != null) {
            throw ProxyUtils.unwrapInvocationThrowable(err);
        }

        return null;
    }

    /**
     * Wraps a target instance and an {@link AutoCloseable} delegate into a proxy instance that closes both when wrapper
     * {@link AutoCloseable#close() close} method called.
     *
     * @param  <T>         The generic {@link AutoCloseable} wrapping interface
     * @param  proxyTarget The (never {@code null}) target instance - if not {@link AutoCloseable} then it's
     *                     {@code close()} method will not be invoked (i.e., only the delegate)
     * @param  type        The target wrapping interface
     * @param  delegate    The (never {@code null}) delegate to close. <B>Note:</B> the delegate is closed <U>after</U>
     *                     the target instance.
     * @return             The wrapping proxy
     */
    public static <T extends AutoCloseable> T wrapDelegateCloseable(
            Object proxyTarget, Class<T> type, AutoCloseable delegate) {
        return ProxyUtils.newProxyInstance(type, new AutoCloseableDelegateInvocationHandler(proxyTarget, delegate));
    }

    public static boolean isCloseMethodInvocation(Method m, Object[] args) {
        return isCloseMethod(m) && GenericUtils.isEmpty(args);
    }

    public static boolean isCloseMethod(Method m) {
        int mods = (m == null) ? 0 : m.getModifiers();
        return (m != null)
                && "close".equals(m.getName())
                && Modifier.isPublic(mods)
                && (!Modifier.isStatic(mods))
                && (void.class == m.getReturnType())
                && GenericUtils.isEmpty(m.getParameterTypes());
    }
}
