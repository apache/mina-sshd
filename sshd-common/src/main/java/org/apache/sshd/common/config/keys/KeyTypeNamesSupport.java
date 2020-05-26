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

package org.apache.sshd.common.config.keys;

import java.util.Collection;
import java.util.Collections;
import java.util.NavigableSet;

import org.apache.sshd.common.util.GenericUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface KeyTypeNamesSupport {
    /**
     * @return The case insensitive {@link NavigableSet} of {@code OpenSSH} key type names that are supported by this
     *         decoder - e.g., {@code ssh-rsa, ssh-dss, ecdsa-sha2-nistp384}. This is not a single name - e.g., ECDSA
     *         keys have several curve names. <B>Caveat:</B> this collection may be un-modifiable...
     */
    NavigableSet<String> getSupportedKeyTypes();

    /**
     * @param  <S>        Generic supporter type
     * @param  typeName   The {@code OpenSSH} key type e.g., {@code ssh-rsa, ssh-dss, ecdsa-sha2-nistp384}. Ignored if
     *                    {@code null}/empty.
     * @param  supporters The {@link KeyTypeNamesSupport}-ers to query - ignored if {@code null}/empty.
     * @return            The <U>first</U> instance whose {@link #getSupportedKeyTypes()} contains the type name.
     */
    static <S extends KeyTypeNamesSupport> S findSupporterByKeyTypeName(String typeName, Collection<? extends S> supporters) {
        return (GenericUtils.isEmpty(typeName) || GenericUtils.isEmpty(supporters))
                ? null
                : supporters.stream()
                        .filter(s -> {
                            Collection<String> names = (s == null)
                                    ? Collections.emptyNavigableSet()
                                    : s.getSupportedKeyTypes();
                            return GenericUtils.isNotEmpty(names) && names.contains(typeName);
                        }).findFirst()
                        .orElse(null);
    }
}
