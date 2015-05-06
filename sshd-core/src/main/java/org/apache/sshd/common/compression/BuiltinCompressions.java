/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.compression;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinCompressions implements NamedFactory<Compression>, OptionalFeature {
    none(Constants.NONE) {
            @Override
            public Compression create() {
                return null;
            }
        },
    zlib(Constants.ZLIB) {
            @Override
            public Compression create() {
                return new CompressionZlib();
            }        
        },
    delayedZlib(Constants.DELAYED_ZLIB) {
            @Override
            public Compression create() {
                return new CompressionDelayedZlib();
            }        
        };
    
    private final String    name;

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final String toString() {
        return getName();
    }

    public final boolean isSupported() {
        return true;
    }

    BuiltinCompressions(String n) {
        name = n;
    }

    public static final Set<BuiltinCompressions> VALUES=
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinCompressions.class));
    public static final BuiltinCompressions fromFactoryName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }
        
        for (BuiltinCompressions c : VALUES) {
            if (name.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }
        
        return null;
    }
    public static final class Constants {
        public static final String  NONE="none";
        public static final String  ZLIB="zlib";
        public static final String  DELAYED_ZLIB="zlib@openssh.com";
    }
}
