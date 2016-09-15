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

import java.util.Objects;
import java.util.function.Function;

/**
 * @param <I> Input type
 * @param <O> Output type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface Transformer<I, O> extends Function<I, O> {
    /**
     * Invokes {@link Objects#toString(Object, String)} on the argument
     * with {@code null} as the value to return if argument is {@code null}
     */
    Transformer<Object, String> TOSTRING = input -> Objects.toString(input, null);

    /**
     * Returns {@link Enum#name()} or {@code null} if argument is {@code null}
     */
    Transformer<Enum<?>, String> ENUM_NAME_EXTRACTOR = input -> {
        if (input == null) {
            return null;
        } else {
            return input.name();
        }
    };

    @Override
    default O apply(I input) {
        return transform(input);
    }
    /**
     * @param input Input value
     * @return Transformed output value
     */
    O transform(I input);

    // CHECKSTYLE:OFF
    @Deprecated
    final class Utils {
    // CHECKSTYLE:ON

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static <U extends V, V> Transformer<U, V> identity() {
            return Transformer.identity();
        }
    }

    static <U extends V, V> Transformer<U, V> identity() {
        return input -> input;
    }

}
