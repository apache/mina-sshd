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

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A dummy map that ignores all {@code put/remove} calls
 *
 * @param  <K> Key type
 * @param  <V> Value type
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class IgnoringEmptyMap<K, V> implements Map<K, V> {
    @SuppressWarnings("rawtypes")
    private static final IgnoringEmptyMap INSTANCE = new IgnoringEmptyMap();

    public IgnoringEmptyMap() {
        super();
    }

    @Override
    public int size() {
        return 0;
    }

    @Override
    public boolean isEmpty() {
        return true;
    }

    @Override
    public boolean containsValue(Object value) {
        Objects.requireNonNull(value, "No value provided");
        return false;
    }

    @Override
    public boolean containsKey(Object key) {
        Objects.requireNonNull(key, "No key provided");
        return false;
    }

    @Override
    public V get(Object key) {
        Objects.requireNonNull(key, "No key provided");
        return null;
    }

    @Override
    public V put(K key, V value) {
        Objects.requireNonNull(key, "No key provided");
        Objects.requireNonNull(value, "No value provided");
        return null;
    }

    @Override
    public V remove(Object key) {
        Objects.requireNonNull(key, "No key provided");
        return null;
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> m) {
        // ignored
    }

    @Override
    public void clear() {
        // ignored
    }

    @Override
    public Set<K> keySet() {
        return Collections.emptySet();
    }

    @Override
    public Collection<V> values() {
        return Collections.emptyList();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof IgnoringEmptyMap<?, ?>;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public String toString() {
        return "{}";
    }

    @Override
    public Set<Entry<K, V>> entrySet() {
        return Collections.emptySet();
    }

    @SuppressWarnings("unchecked")
    public static <K, V> IgnoringEmptyMap<K, V> getInstance() {
        return INSTANCE;
    }
}
