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
package org.apache.sshd.common.random;

import java.util.Objects;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;

/**
 * A random factory wrapper that uses a single random instance. The underlying random instance has to be thread safe.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SingletonRandomFactory extends AbstractRandom implements RandomFactory {

    private final NamedFactory<Random> factory;
    private final Random random;

    public SingletonRandomFactory(NamedFactory<Random> factory) {
        this.factory = Objects.requireNonNull(factory, "No factory");
        this.random = Objects.requireNonNull(factory.create(), "No random instance created");
    }

    @Override
    public boolean isSupported() {
        if (factory instanceof OptionalFeature) {
            return ((OptionalFeature) factory).isSupported();
        } else {
            return true;
        }
    }

    @Override
    public void fill(byte[] bytes, int start, int len) {
        random.fill(bytes, start, len);
    }

    @Override
    public int random(int max) {
        return random.random(max);
    }

    @Override
    public String getName() {
        return factory.getName();
    }

    @Override
    public Random create() {
        return this;
    }
}
