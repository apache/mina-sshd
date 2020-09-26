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

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.channels.Channel;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ProxyUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps a target instance and a {@link Channel} delegate into a proxy instance that closes both when wrapper
 * {@link AutoCloseable#close() close} method called. The {@link Channel#isOpen()} call is invoked only on the delegate
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NioChannelDelegateInvocationHandler extends AutoCloseableDelegateInvocationHandler {
    public NioChannelDelegateInvocationHandler(Object proxyTarget, Channel delegate) {
        super(proxyTarget, delegate);
    }

    public Channel getChannelDelegate() {
        return Channel.class.cast(super.getAutoCloseableDelegate());
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (!isQueryOpenMethodInvocation(method, args)) {
            return super.invoke(proxy, method, args);
        }

        Channel channelDelegate = getChannelDelegate();
        try {
            return method.invoke(channelDelegate, args);
        } catch (Throwable t) {
            Class<?> targetType = channelDelegate.getClass();
            Logger log = LoggerFactory.getLogger(targetType);
            LoggingUtils.debug(log, "invoke({}#{}) failed ({}) to execute: {}",
                    targetType.getSimpleName(), method.getName(), t.getClass().getSimpleName(), t.getMessage(), t);
            throw ProxyUtils.unwrapInvocationThrowable(t);
        }
    }

    /**
     * Wraps a target instance and a {@link Channel} delegate into a proxy instance that closes both when wrapper
     * {@link Channel#close() close} method called. The {@link Channel#isOpen()} call is invoked only on the delegate
     *
     * @param  <T>         The generic {@link Channel} wrapping interface
     * @param  proxyTarget The (never {@code null}) target instance - if not {@link AutoCloseable} then it's
     *                     {@code close()} method will not be invoked (i.e., only the delegate)
     * @param  type        The target wrapping interface
     * @param  delegate    The (never {@code null}) delegate to use. <B>Note:</B> the delegate is closed <U>after</U>
     *                     the target instance.
     * @return             The wrapping proxy
     */
    public static <T extends Channel> T wrapDelegateChannel(
            Object proxyTarget, Class<T> type, Channel delegate) {
        return ProxyUtils.newProxyInstance(type, new NioChannelDelegateInvocationHandler(proxyTarget, delegate));
    }

    public static boolean isQueryOpenMethodInvocation(Method m, Object[] args) {
        return isQueryOpenMethodInvocation(m) && GenericUtils.isEmpty(args);
    }

    public static boolean isQueryOpenMethodInvocation(Method m) {
        int mods = (m == null) ? 0 : m.getModifiers();
        return (m != null)
                && "isOpen".equals(m.getName())
                && Modifier.isPublic(mods)
                && (!Modifier.isStatic(mods))
                && (boolean.class == m.getReturnType())
                && GenericUtils.isEmpty(m.getParameterTypes());
    }
}
