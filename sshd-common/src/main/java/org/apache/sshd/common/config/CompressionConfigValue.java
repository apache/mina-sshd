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

package org.apache.sshd.common.config;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Provides a &quot;bridge&quot; between the configuration values and the actual
 * {@link org.apache.sshd.common.NamedFactory} for the {@link Compression}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum CompressionConfigValue implements CompressionFactory {
    YES(BuiltinCompressions.zlib),
    NO(BuiltinCompressions.none),
    DELAYED(BuiltinCompressions.delayedZlib);

    public static final Set<CompressionConfigValue> VALUES
            = Collections.unmodifiableSet(EnumSet.allOf(CompressionConfigValue.class));

    private final CompressionFactory factory;

    CompressionConfigValue(CompressionFactory delegate) {
        factory = delegate;
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    @Override
    public final Compression create() {
        return factory.create();
    }

    @Override
    public boolean isSupported() {
        return factory.isSupported();
    }

    @Override
    public final String toString() {
        return getName();
    }

    @Override
    public boolean isDelayed() {
        return factory.isDelayed();
    }

    @Override
    public boolean isCompressionExecuted() {
        return factory.isCompressionExecuted();
    }

    public static CompressionConfigValue fromName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (CompressionConfigValue v : VALUES) {
            if (n.equalsIgnoreCase(v.name())) {
                return v;
            }
        }

        return null;
    }
}
