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
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A named factory is a factory identified by a name. Such names are used mainly in the algorithm negotiation at the
 * beginning of the SSH connection.
 *
 * @param  <T> The create object instance type
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface NamedFactory<T> extends Factory<T>, NamedResource {
    /**
     * Create an instance of the specified name by looking up the needed factory in the list.
     *
     * @param  factories list of available factories
     * @param  name      the factory name to use
     * @param  <T>       type of object to create
     * @return           a newly created object or {@code null} if the factory is not in the list
     */
    static <T> T create(Collection<? extends NamedFactory<? extends T>> factories, String name) {
        NamedFactory<? extends T> f = NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, factories);
        if (f != null) {
            return f.create();
        } else {
            return null;
        }
    }

    static <S extends OptionalFeature, E extends NamedResource> List<E> setUpTransformedFactories(
            boolean ignoreUnsupported, Collection<? extends S> preferred, Function<? super S, ? extends E> xform) {
        return preferred.stream()
                .filter(f -> ignoreUnsupported || f.isSupported())
                .map(xform)
                .collect(Collectors.toList());
    }

    static <E extends NamedResource & OptionalFeature> List<E> setUpBuiltinFactories(
            boolean ignoreUnsupported, Collection<? extends E> preferred) {
        return preferred.stream()
                .filter(f -> ignoreUnsupported || f.isSupported())
                .collect(Collectors.toList());
    }
}
