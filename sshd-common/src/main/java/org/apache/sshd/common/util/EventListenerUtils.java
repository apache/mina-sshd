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

import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EventListener;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class EventListenerUtils {
    /**
     * A special &quot;comparator&quot; whose only purpose is to ensure there are no same references in a listener's set
     * - to be used in conjunction with a {@code TreeSet} as its comparator
     */
    @SuppressWarnings("checkstyle:anoninnerlength")
    public static final Comparator<EventListener> LISTENER_INSTANCE_COMPARATOR = (l1, l2) -> {
        if (l1 == l2) {
            return 0;
        } else if (l1 == null) {
            return 1;
        } else if (l2 == null) {
            return -1;
        }

        Class<?> c1 = l1.getClass();
        Class<?> c2 = l2.getClass();
        boolean checkHashCodes = true;
        if (Proxy.isProxyClass(c1)) {
            if (Proxy.isProxyClass(c2)) {
                checkHashCodes = false; // cannot call hashCode on a proxy
            } else {
                return 1;
            }
        } else if (Proxy.isProxyClass(c2)) {
            return -1;
        }

        if (checkHashCodes) {
            int nRes = Integer.compare(l1.hashCode(), l2.hashCode());
            if (nRes != 0) {
                return nRes;
            }
        }

        int nRes = Integer.compare(System.identityHashCode(l1), System.identityHashCode(l2));
        if (nRes != 0) {
            return nRes;
        }

        if (c1 != c2) {
            return c1.getName().compareTo(c2.getName());
        }

        String s1 = Objects.toString(l1.toString(), "");
        String s2 = Objects.toString(l2.toString(), "");
        nRes = s1.compareTo(s2);
        if (nRes != 0) {
            return nRes;
        }
        throw new UnsupportedOperationException("Ran out of options to compare instance of " + s1 + " vs. " + s2);
    };

    private EventListenerUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param  <L>       Type of {@link SshdEventListener} contained in the set
     * @param  listeners The listeners to pre-add to the create set - ignored if (@code null}/empty
     * @return           A (synchronized) {@link Set} for containing the listeners ensuring that if same listener
     *                   instance is added repeatedly only <U>one</U> instance is actually contained
     */
    public static <L extends SshdEventListener> Set<L> synchronizedListenersSet(Collection<? extends L> listeners) {
        Set<L> s = EventListenerUtils.synchronizedListenersSet();
        if (GenericUtils.size(listeners) > 0) {
            s.addAll(listeners);
        }

        return s;
    }

    /**
     * @param  <L> Type of {@link SshdEventListener} contained in the set
     * @return     A (synchronized) {@link Set} for containing the listeners ensuring that if same listener instance is
     *             added repeatedly only <U>one</U> instance is actually contained
     * @see        #LISTENER_INSTANCE_COMPARATOR
     */
    public static <L extends SshdEventListener> Set<L> synchronizedListenersSet() {
        return Collections.synchronizedSet(new TreeSet<L>(LISTENER_INSTANCE_COMPARATOR));
    }

    /**
     * Provides proxy wrapper around an {@link Iterable} container of listener interface implementation. <b>Note:</b> a
     * listener interface is one whose invoked methods return <u>only</u> {@code void}.
     *
     * @param  <T>          Generic listener type
     * @param  listenerType The expected listener <u>interface</u>
     * @param  listeners    An {@link Iterable} container of listeners to be invoked.
     *                      <p>
     *                      <b>Note(s):</b>
     *                      </p>
     *                      <ul>
     *                      <li>
     *                      <p>
     *                      The invocation order is same as the {@link Iterable} container
     *                      </p>
     *                      </li>
     *
     *                      <li>
     *                      <p>
     *                      If any of the invoked listener methods throws an exception, the rest of the listener are
     *                      <u>not</u> invoked and the exception is propagated to the caller
     *                      </p>
     *                      </li>
     *
     *                      <li>
     *                      <p>
     *                      It is up to the <u>caller</u> to ensure that the container does not change while the proxy
     *                      is invoked
     *                      </p>
     *                      </li>
     *                      </ul>
     * @return              A proxy wrapper implementing the same interface, but delegating the calls to the container
     * @see                 #proxyWrapper(Class, ClassLoader, Iterable)
     */
    public static <T extends SshdEventListener> T proxyWrapper(Class<T> listenerType, Iterable<? extends T> listeners) {
        return proxyWrapper(listenerType, listenerType.getClassLoader(), listeners);
    }

    /**
     * Provides proxy wrapper around an {@link Iterable} container of listener interface implementation. <b>Note:</b> a
     * listener interface is one whose invoked methods return <u>only</u> {@code void}.
     *
     * @param  <T>                      Generic {@link SshdEventListener} type
     * @param  listenerType             The expected listener <u>interface</u>
     * @param  loader                   The {@link ClassLoader} to use for the proxy
     * @param  listeners                An {@link Iterable} container of listeners to be invoked.
     *                                  <p>
     *                                  <b>Note(s):</b>
     *                                  </p>
     *                                  <ul>
     *                                  <li>
     *                                  <p>
     *                                  The invocation order is same as the {@link Iterable} container
     *                                  </p>
     *                                  </li>
     *
     *                                  <li>
     *                                  <p>
     *                                  If any of the invoked listener methods throws an exception, the rest of the
     *                                  listener are <u>not</u> invoked and the exception is propagated to the caller
     *                                  </p>
     *                                  </li>
     *
     *                                  <li>
     *                                  <p>
     *                                  It is up to the <u>caller</u> to ensure that the container does not change while
     *                                  the proxy is invoked
     *                                  </p>
     *                                  </li>
     *                                  </ul>
     * @return                          A proxy wrapper implementing the same interface, but delegating the calls to the
     *                                  container
     * @throws IllegalArgumentException if <tt>listenerType</tt> is not an interface or a {@code null} container has
     *                                  been provided
     * @see                             #proxyWrapper(Class, ClassLoader, Iterable)
     */
    public static <T extends SshdEventListener> T proxyWrapper(
            Class<T> listenerType, ClassLoader loader, Iterable<? extends T> listeners) {
        Objects.requireNonNull(listeners, "No listeners container provided");

        return ProxyUtils.newProxyInstance(loader, listenerType, (proxy, method, args) -> {
            Throwable err = null;
            for (T l : listeners) {
                try {
                    method.invoke(l, args);
                } catch (Throwable t) {
                    Throwable e = GenericUtils.peelException(t);
                    err = GenericUtils.accumulateException(err, e);
                }
            }

            if (err != null) {
                throw ProxyUtils.unwrapInvocationThrowable(err);
            }

            return null; // we assume always void return value...
        });
    }
}
