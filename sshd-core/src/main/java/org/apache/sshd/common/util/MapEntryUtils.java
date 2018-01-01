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

import java.util.Comparator;
import java.util.Map;

/**
 * Represents an un-modifiable pair of values
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class MapEntryUtils {
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final Comparator<Map.Entry<Comparable, ?>> BY_KEY_COMPARATOR = (o1, o2) -> {
        Comparable k1 = o1.getKey();
        Comparable k2 = o2.getKey();
        return k1.compareTo(k2);
    };

    private MapEntryUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param <K> The {@link Comparable} key type
     * @param <V> The associated entry value
     * @return A {@link Comparator} for {@link java.util.Map.Entry}-ies that
     * compares the key values
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static <K extends Comparable<K>, V> Comparator<Map.Entry<K, V>> byKeyEntryComparator() {
        return (Comparator) BY_KEY_COMPARATOR;
    }
}