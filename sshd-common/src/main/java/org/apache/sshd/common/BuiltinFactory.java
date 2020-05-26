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
import java.util.stream.Collectors;

import org.apache.sshd.common.util.GenericUtils;

/**
 * A named optional factory.
 *
 * @param  <T> The create object instance type
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface BuiltinFactory<T> extends NamedFactory<T>, OptionalFeature {
    static <T, E extends BuiltinFactory<T>> List<NamedFactory<T>> setUpFactories(
            boolean ignoreUnsupported, Collection<? extends E> preferred) {
        return GenericUtils.stream(preferred)
                .filter(f -> ignoreUnsupported || f.isSupported())
                .collect(Collectors.toList());
    }
}
