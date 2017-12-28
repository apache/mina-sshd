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

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collection;
import java.util.Map;

/**
 * The complement to the {@code Callable} interface - accepts one argument
 * and possibly throws somethind
 *
 * @param <ARG> Argument type
 * @param <RET> Return type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface Invoker<ARG, RET> {
    RET invoke(ARG arg) throws Throwable;

    static <ARG> Invoker<ARG, Void> wrapAll(Collection<? extends Invoker<? super ARG, ?>> invokers) {
        return arg -> {
            invokeAll(arg, invokers);
            return null;
        };
    }

    /**
     * Invokes <U>all</U> the instances ignoring the return value. Any
     * intermediate exceptions are accumulated and thrown at the end.
     *
     * @param <ARG> Argument type
     * @param arg The argument to pass to the {@link #invoke(Object)} method
     * @param invokers The invokers to scan - ignored if {@code null}/empty
     * (also ignores {@code null} members)
     * @throws Throwable If invocation failed
     */
    static <ARG> void invokeAll(ARG arg, Collection<? extends Invoker<? super ARG, ?>> invokers) throws Throwable {
        if (GenericUtils.isEmpty(invokers)) {
            return;
        }

        Throwable err = null;
        for (Invoker<? super ARG, ?> i : invokers) {
            if (i == null) {
                continue;
            }

            try {
                i.invoke(arg);
            } catch (Throwable t) {
                err = GenericUtils.accumulateException(err, t);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    static <ARG> Invoker<ARG, Void> wrapFirst(Collection<? extends Invoker<? super ARG, ?>> invokers) {
        return arg -> {
            Map.Entry<Invoker<? super ARG, ?>, Throwable> result = invokeTillFirstFailure(arg, invokers);
            if (result != null) {
                throw result.getValue();
            }
            return null;
        };
    }

    /**
     * Invokes all instances until 1st failure (if any)
     *
     * @param <ARG> Argument type
     * @param arg The argument to pass to the {@link #invoke(Object)} method
     * @param invokers The invokers to scan - ignored if {@code null}/empty
     * (also ignores {@code null} members)
     * @return A {@link SimpleImmutableEntry} representing the <U>first</U> failed
     * invocation - {@code null} if all were successful (or none invoked).
     */
    static <ARG> SimpleImmutableEntry<Invoker<? super ARG, ?>, Throwable> invokeTillFirstFailure(ARG arg, Collection<? extends Invoker<? super ARG, ?>> invokers) {
        if (GenericUtils.isEmpty(invokers)) {
            return null;
        }

        for (Invoker<? super ARG, ?> i : invokers) {
            if (i == null) {
                continue;
            }

            try {
                i.invoke(arg);
            } catch (Throwable t) {
                return new SimpleImmutableEntry<>(i, t);
            }
        }

        return null;
    }
}
