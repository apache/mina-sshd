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

package org.apache.sshd.common.io;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.io.mina.MinaServiceFactoryFactory;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactoryFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinIoServiceFactoryFactories implements NamedFactory<IoServiceFactoryFactory> {
    NIO2(Nio2ServiceFactoryFactory.class),
    NMINA(MinaServiceFactoryFactory.class);

    public static final Set<BuiltinIoServiceFactoryFactories> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinIoServiceFactoryFactories.class));

    private final Class<? extends IoServiceFactoryFactory> factoryClass;

    BuiltinIoServiceFactoryFactories(Class<? extends IoServiceFactoryFactory> clazz) {
        factoryClass = clazz;
    }

    public final Class<? extends IoServiceFactoryFactory> getFactoryClass() {
        return factoryClass;
    }

    @Override
    public final String getName() {
        return name().toLowerCase();
    }

    @Override
    public final IoServiceFactoryFactory create() {
        Class<? extends IoServiceFactoryFactory> clazz = getFactoryClass();
        try {
            return clazz.newInstance();
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    public static BuiltinIoServiceFactoryFactories fromFactoryName(String name) {
        return NamedResource.Utils.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    public static BuiltinIoServiceFactoryFactories fromFactoryClass(Class<?> clazz) {
        if ((clazz == null) || (!IoServiceFactoryFactory.class.isAssignableFrom(clazz))) {
            return null;
        }

        for (BuiltinIoServiceFactoryFactories f : VALUES) {
            if (clazz.isAssignableFrom(f.getFactoryClass())) {
                return f;
            }
        }

        return null;
    }
}
