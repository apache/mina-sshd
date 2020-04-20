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

package org.apache.sshd.common;

import java.util.Objects;
import java.util.function.Function;

/**
 * Provides the capability to attach in-memory attributes to the entity
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface AttributeStore extends AttributeRepository {
    /**
     * If the specified key is not already associated with a value (or is mapped to {@code null}), attempts to compute
     * its value using the given mapping function and enters it into this map unless {@code null}.
     *
     * @param  <T>      The generic attribute type
     * @param  key      The key of the attribute; must not be {@code null}.
     * @param  resolver The (never {@code null}) mapping function to use if value not already mapped. If returns
     *                  {@code null} then value is not mapped to the provided key.
     * @return          The resolved value - {@code null} if value not mapped and resolver did not return a
     *                  non-{@code null} value for it
     */
    default <T> T computeAttributeIfAbsent(
            AttributeKey<T> key, Function<? super AttributeKey<T>, ? extends T> resolver) {
        Objects.requireNonNull(resolver, "No resolver provided");

        T value = getAttribute(key);
        if (value != null) {
            return value;
        }

        value = resolver.apply(key);
        if (value == null) {
            return null;
        }

        setAttribute(key, value);
        return value;
    }

    /**
     * Sets a user-defined attribute.
     *
     * @param  <T>   The generic attribute type
     * @param  key   The key of the attribute; must not be {@code null}.
     * @param  value The value of the attribute; must not be {@code null}.
     * @return       The old value of the attribute; {@code null} if it is new.
     */
    <T> T setAttribute(AttributeKey<T> key, T value);

    /**
     * Removes the user-defined attribute
     *
     * @param  <T> The generic attribute type
     * @param  key The key of the attribute; must not be {@code null}.
     * @return     The removed value; {@code null} if no previous value
     */
    <T> T removeAttribute(AttributeKey<T> key);

    /**
     * Removes all currently stored user-defined attributes
     */
    void clearAttributes();
}
