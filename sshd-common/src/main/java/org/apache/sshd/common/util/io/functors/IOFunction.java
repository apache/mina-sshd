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

package org.apache.sshd.common.util.io.functors;

import java.io.IOException;
import java.util.Objects;

/**
 * Invokes some I/O function on the input returning some output and potentially throwing an {@link IOException} in the
 * process
 *
 * @param  <T> Type of input
 * @param  <R> Type of output
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface IOFunction<T, R> {
    R apply(T t) throws IOException;

    /**
     * Returns a composed function that first applies the {@code before} function to its input, and then applies this
     * function to the result. If evaluation of either function throws an exception, it is relayed to the caller of the
     * composed function.
     *
     * @param  <V>                  the type of input to the {@code before} function, and to the composed function
     * @param  before               the function to apply before this function is applied
     * @return                      a composed function that first applies the {@code before} function and then applies
     *                              this function
     * @throws NullPointerException if before is null
     *
     * @see                         #andThen(IOFunction)
     */
    default <V> IOFunction<V, R> compose(IOFunction<? super V, ? extends T> before) {
        Objects.requireNonNull(before, "No composing function provided");
        return (V v) -> apply(before.apply(v));
    }

    /**
     * Returns a composed function that first applies this function to its input, and then applies the {@code after}
     * function to the result. If evaluation of either function throws an exception, it is relayed to the caller of the
     * composed function.
     *
     * @param  <V>                  the type of output of the {@code after} function, and of the composed function
     * @param  after                the function to apply after this function is applied
     * @return                      a composed function that first applies this function and then applies the
     *                              {@code after} function
     * @throws NullPointerException if after is null
     *
     * @see                         #compose(IOFunction)
     */
    default <V> IOFunction<T, V> andThen(IOFunction<? super R, ? extends V> after) {
        Objects.requireNonNull(after, "No composing function provided");
        return (T t) -> after.apply(apply(t));
    }

    /**
     * Returns a function that always returns its input argument.
     *
     * @param  <T> the type of the input and output objects to the function
     * @return     a function that always returns its input argument
     */
    static <T> IOFunction<T, T> identity() {
        return t -> t;
    }
}
