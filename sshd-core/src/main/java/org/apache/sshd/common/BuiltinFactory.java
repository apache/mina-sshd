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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A named optional factory.
 *
 * @param <T> The create object instance type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface BuiltinFactory<T> extends NamedFactory<T>, OptionalFeature {

    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static <T, E extends BuiltinFactory<T>> List<NamedFactory<T>> setUpFactories(
                boolean ignoreUnsupported, Collection<? extends E> preferred) {
            List<NamedFactory<T>> avail = new ArrayList<>(preferred.size());
            for (E f : preferred) {
                if (ignoreUnsupported || f.isSupported()) {
                    avail.add(f);
                }
            }
            return avail;
        }
    }
}
