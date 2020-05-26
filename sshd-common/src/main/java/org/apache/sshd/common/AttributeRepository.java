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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface AttributeRepository {
    /**
     * <P>
     * Type safe key for storage of user attributes. Typically it is used as a static variable that is shared between
     * the producer and the consumer. To further restrict access the setting or getting it from the store one can add
     * static {@code get/set methods} e.g:
     * </P>
     *
     * <pre>
     * <code>
     * public static final AttributeKey&lt;MyValue&gt; MY_KEY = new AttributeKey&lt;MyValue&gt;();
     *
     * public static MyValue getMyValue(Session s) {
     *   return s.getAttribute(MY_KEY);
     * }
     *
     * public static void setMyValue(Session s, MyValue value) {
     *   s.setAttribute(MY_KEY, value);
     * }
     * </code>
     * </pre>
     *
     * @param  <T> type of value stored in the attribute.
     * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    // CHECKSTYLE:OFF
    class AttributeKey<T> {
        public AttributeKey() {
            super();
        }
    }
    // CHECKSTYLE:ON

    /**
     * @return Current number of user-defined attributes stored in the repository
     */
    int getAttributesCount();

    /**
     * Returns the value of the user-defined attribute.
     *
     * @param  <T> The generic attribute type
     * @param  key The key of the attribute; must not be {@code null}.
     * @return     {@code null} if there is no value associated with the specified key
     */
    <T> T getAttribute(AttributeKey<T> key);

    /**
     * Attempts to resolve the associated value by going up the store's hierarchy (if any)
     *
     * @param  <T> The generic attribute type
     * @param  key The key of the attribute; must not be {@code null}.
     * @return     {@code null} if there is no value associated with the specified key either in this repository or any
     *             of its ancestors (if any available)
     */
    default <T> T resolveAttribute(AttributeKey<T> key) {
        return getAttribute(key);
    }

    /**
     * @return A {@link Collection} <u>snapshot</u> of all the currently registered attributes in the repository
     */
    Collection<AttributeKey<?>> attributeKeys();

    static <A> AttributeRepository ofKeyValuePair(AttributeKey<A> key, A value) {
        Objects.requireNonNull(key, "No key provided");
        Objects.requireNonNull(value, "No value provided");
        return ofAttributesMap(Collections.singletonMap(key, value));
    }

    static AttributeRepository ofAttributesMap(Map<AttributeKey<?>, ?> attributes) {
        return new AttributeRepository() {
            @Override
            public int getAttributesCount() {
                return attributes.size();
            }

            @Override
            @SuppressWarnings("unchecked")
            public <T> T getAttribute(AttributeKey<T> key) {
                Objects.requireNonNull(key, "No key provided");
                return GenericUtils.isEmpty(attributes) ? null : (T) attributes.get(key);
            }

            @Override
            public Collection<AttributeKey<?>> attributeKeys() {
                return GenericUtils.isEmpty(attributes)
                        ? Collections.emptySet()
                        : new HashSet<>(attributes.keySet());
            }

            @Override
            public String toString() {
                return AttributeRepository.class.getSimpleName() + "[" + attributes + "]";
            }
        };
    }
}
