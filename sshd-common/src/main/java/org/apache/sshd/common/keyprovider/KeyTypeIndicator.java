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

package org.apache.sshd.common.keyprovider;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface KeyTypeIndicator {
    /**
     * @return The <U>SSH</U> key type name - e.g., &quot;ssh-rsa&quot;, &quot;sshd-dss&quot; etc.
     */
    String getKeyType();

    /**
     * @param  <I>        The {@link KeyTypeIndicator}
     * @param  indicators The indicators to group
     * @return            A {@link NavigableMap} where key=the case <U>insensitive</U> {@link #getKeyType() key type},
     *                    value = the {@link List} of all indicators having the same key type
     */
    static <I extends KeyTypeIndicator> NavigableMap<String, List<I>> groupByKeyType(Collection<? extends I> indicators) {
        return GenericUtils.isEmpty(indicators)
                ? Collections.emptyNavigableMap()
                : indicators.stream()
                        .collect(Collectors.groupingBy(
                                KeyTypeIndicator::getKeyType, () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER),
                                Collectors.toList()));
    }
}
