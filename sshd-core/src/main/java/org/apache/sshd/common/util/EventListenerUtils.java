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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.EventListener;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EventListenerUtils {
    /**
     * Provides proxy wrapper around an {@link Iterable} container of listener
     * interface implementation. <b>Note:</b> a listener interface is one whose
     * invoked methods return <u>only</u> {@code void}.
     *
     * @param listenerType The expected listener <u>interface</u>
     * @param listeners    An {@link Iterable} container of listeners to be invoked.</P>
     *                     <b>Note(s):</b>
     *                     <ul>
     *                     <li>The invocation order is same as the {@link Iterable} container</li>
     *                     <p/>
     *                     <li>If any of the invoked listener methods throws an exception, the
     *                     rest of the listener are <u>not</u> invoked and the exception is
     *                     propagated to the caller</li>
     *                     <p/>
     *                     <li>It is up to the <u>caller</u> to ensure that the container does
     *                     not change while the proxy is invoked</li>
     *                     </ul>
     * @return A proxy wrapper implementing the same interface, but delegating
     * the calls to the container
     * @see #proxyWrapper(Class, ClassLoader, Iterable)
     */
    public static <T extends EventListener> T proxyWrapper(Class<T> listenerType, Iterable<? extends T> listeners) {
        return proxyWrapper(listenerType, listenerType.getClassLoader(), listeners);
    }

    /**
     * Provides proxy wrapper around an {@link Iterable} container of listener
     * interface implementation. <b>Note:</b> a listener interface is one whose
     * invoked methods return <u>only</u> {@code void}.
     *
     * @param listenerType The expected listener <u>interface</u>
     * @param loader       The {@link ClassLoader} to use for the proxy
     * @param listeners    An {@link Iterable} container of listeners to be invoked.</P>
     *                     <b>Note(s):</b>
     *                     <ul>
     *                     <li>The invocation order is same as the {@link Iterable} container</li>
     *                     <p/>
     *                     <li>If any of the invoked listener methods throws an exception, the
     *                     rest of the listener are <u>not</u> invoked and the exception is
     *                     propagated to the caller</li>
     *                     <p/>
     *                     <li>It is up to the <u>caller</u> to ensure that the container does
     *                     not change while the proxy is invoked</li>
     *                     </ul>
     * @return A proxy wrapper implementing the same interface, but delegating
     * the calls to the container
     * @throws IllegalArgumentException if <tt>listenerType</tt> is not an interface
     *                                  or a {@code null} container has been provided
     * @see #proxyWrapper(Class, ClassLoader, Iterable)
     */
    public static <T extends EventListener> T proxyWrapper(Class<T> listenerType, ClassLoader loader, final Iterable<? extends T> listeners) {
        if ((listenerType == null) || (!listenerType.isInterface())) {
            throw new IllegalArgumentException("Target proxy is not an interface");
        }

        if (listeners == null) {
            throw new IllegalArgumentException("No listeners container provided");
        }

        Object wrapper = Proxy.newProxyInstance(loader, new Class<?>[]{listenerType}, new InvocationHandler() {
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                for (T l : listeners) {
                    method.invoke(l, args);
                }
                return null;    // we assume always void return value...
            }
        });
        return listenerType.cast(wrapper);
    }
}
