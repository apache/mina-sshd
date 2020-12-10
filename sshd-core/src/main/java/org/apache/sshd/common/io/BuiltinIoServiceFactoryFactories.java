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
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactoryFactory;
import org.apache.sshd.common.util.ReflectionUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinIoServiceFactoryFactories implements NamedFactory<IoServiceFactoryFactory>, OptionalFeature {
    NIO2(Nio2ServiceFactoryFactory.class),
    MINA("org.apache.sshd.common.io.mina.MinaServiceFactoryFactory"),
    NETTY("org.apache.sshd.netty.NettyIoServiceFactoryFactory");

    public static final Set<BuiltinIoServiceFactoryFactories> VALUES
            = Collections.unmodifiableSet(EnumSet.allOf(BuiltinIoServiceFactoryFactories.class));

    private final Class<? extends IoServiceFactoryFactory> factoryClass;
    private final String factoryClassName;

    BuiltinIoServiceFactoryFactories(Class<? extends IoServiceFactoryFactory> clazz) {
        factoryClass = clazz;
        factoryClassName = null;
    }

    BuiltinIoServiceFactoryFactories(String clazz) {
        factoryClass = null;
        factoryClassName = clazz;
    }

    public final String getFactoryClassName() {
        if (factoryClass != null) {
            return factoryClass.getName();
        } else {
            return factoryClassName;
        }
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public final Class<? extends IoServiceFactoryFactory> getFactoryClass() {
        if (factoryClass != null) {
            return factoryClass;
        }

        try {
            return (Class) Class.forName(factoryClassName, true, BuiltinIoServiceFactoryFactories.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            try {
                return (Class) Class.forName(factoryClassName, true, Thread.currentThread().getContextClassLoader());
            } catch (ClassNotFoundException e1) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public final String getName() {
        return name().toLowerCase();
    }

    @Override
    public final IoServiceFactoryFactory create() {
        Class<? extends IoServiceFactoryFactory> clazz = getFactoryClass();
        try {
            return ReflectionUtils.newInstance(clazz, IoServiceFactoryFactory.class);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public boolean isSupported() {
        try {
            return getFactoryClass() != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static BuiltinIoServiceFactoryFactories fromFactoryName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    public static BuiltinIoServiceFactoryFactories fromFactoryClass(Class<?> clazz) {
        if ((clazz == null) || (!IoServiceFactoryFactory.class.isAssignableFrom(clazz))) {
            return null;
        }

        for (BuiltinIoServiceFactoryFactories f : VALUES) {
            if (!f.isSupported()) {
                continue;
            }

            if (clazz.isAssignableFrom(f.getFactoryClass())) {
                return f;
            }
        }

        return null;
    }

}
