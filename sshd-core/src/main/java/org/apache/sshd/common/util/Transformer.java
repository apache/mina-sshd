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

/**
 * @param <I> Input type
 * @param <O> Output type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Transformer<I, O> {
    // TODO in JDK-8 replace this with Function

    /**
     * Invokes {@link Objects#toString(Object, String)} on the argument
     * with {@code null} as the value to return if argument is {@code null}
     */
    Transformer<Object, String> TOSTRING = new Transformer<Object, String>() {
        @Override
        public String transform(Object input) {
            return Objects.toString(input, null);
        }
    };

    /**
     * Returns {@link Enum#name()} or {@code null} if argument is {@code null}
     */
    Transformer<Enum<?>, String> ENUM_NAME_EXTRACTOR = new Transformer<Enum<?>, String>() {
        @Override
        public String transform(Enum<?> input) {
            if (input == null) {
                return null;
            } else {
                return input.name();
            }
        }
    };

    /**
     * @param input Input value
     * @return Transformed output value
     */
    O transform(I input);

    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON

        @SuppressWarnings("rawtypes")
        private static final Transformer IDENTITY = new Transformer() {
            @Override
            public Object transform(Object input) {
                return input;
            }
        };

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        @SuppressWarnings({ "cast", "unchecked" })
        public static <U extends V, V> Transformer<U, V> identity() {
            return (Transformer<U, V>) IDENTITY;
        }
    }
}
