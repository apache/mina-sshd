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

import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ServiceLoader;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultIoServiceFactoryFactory extends AbstractIoServiceFactoryFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultIoServiceFactoryFactory.class);

    private IoServiceFactoryFactory factory;

    protected DefaultIoServiceFactoryFactory() {
        this(null);
    }

    protected DefaultIoServiceFactoryFactory(Factory<CloseableExecutorService> factory) {
        super(factory);
    }

    @Override
    public IoServiceFactory create(FactoryManager manager) {
        IoServiceFactoryFactory factoryInstance = getIoServiceProvider();
        return factoryInstance.create(manager);
    }

    /**
     * @return The actual {@link IoServiceFactoryFactory} being delegated
     */
    public IoServiceFactoryFactory getIoServiceProvider() {
        synchronized (this) {
            if (factory != null) {
                return factory;
            }

            factory = newInstance(IoServiceFactoryFactory.class);
            if (factory == null) {
                factory = BuiltinIoServiceFactoryFactories.NIO2.create();
                log.info("No detected/configured " + IoServiceFactoryFactory.class.getSimpleName()
                         + " using " + factory.getClass().getSimpleName());
            } else {
                log.info("Using {}", factory.getClass().getSimpleName());
            }

            Factory<CloseableExecutorService> executorServiceFactory = getExecutorServiceFactory();
            if (executorServiceFactory != null) {
                factory.setExecutorServiceFactory(executorServiceFactory);
            }
        }

        return factory;
    }

    public static <T extends IoServiceFactoryFactory> T newInstance(Class<T> clazz) {
        String propName = clazz.getName();
        String factory = System.getProperty(propName);
        if (!GenericUtils.isEmpty(factory)) {
            return newInstance(clazz, factory);
        }

        Thread currentThread = Thread.currentThread();
        ClassLoader cl = currentThread.getContextClassLoader();
        if (cl != null) {
            T t = tryLoad(propName, ServiceLoader.load(clazz, cl));
            if (t != null) {
                return t;
            }
        }

        ClassLoader clDefault = DefaultIoServiceFactoryFactory.class.getClassLoader();
        if (cl != clDefault) {
            T t = tryLoad(propName, ServiceLoader.load(clazz, clDefault));
            if (t != null) {
                return t;
            }
        }

        return null;
    }

    public static <T extends IoServiceFactoryFactory> T tryLoad(String propName, ServiceLoader<T> loader) {
        Iterator<T> it = loader.iterator();
        Deque<T> services = new LinkedList<>();
        try {
            while (it.hasNext()) {
                try {
                    T instance = it.next();
                    services.add(instance);
                } catch (Throwable t) {
                    LOGGER.warn("Exception while instantiating factory from ServiceLoader", t);
                }
            }
        } catch (Throwable t) {
            LOGGER.warn("Exception while loading factory from ServiceLoader", t);
        }

        int numDetected = services.size();
        if (numDetected <= 0) {
            return null;
        }

        if (numDetected != 1) {
            LOGGER.error("Multiple ({}) registered instances detected:", numDetected);
            for (T s : services) {
                LOGGER.error("===> {}", s.getClass().getName());
            }
            throw new IllegalStateException(
                    "Multiple (" + numDetected + ")"
                                            + " registered " + IoServiceFactoryFactory.class.getSimpleName()
                                            + " instances detected."
                                            + " Please use -D" + propName + "=...factory class.. to select one"
                                            + " or remove the extra providers from the classpath");
        }

        return services.removeFirst();
    }

    public static <T extends IoServiceFactoryFactory> T newInstance(Class<? extends T> clazz, String factory) {
        BuiltinIoServiceFactoryFactories builtin = BuiltinIoServiceFactoryFactories.fromFactoryName(factory);
        if (builtin != null) {
            IoServiceFactoryFactory builtinInstance = builtin.create();
            return clazz.cast(builtinInstance);
        }

        Thread currentThread = Thread.currentThread();
        ClassLoader cl = currentThread.getContextClassLoader();
        if (cl != null) {
            try {
                Class<?> loaded = cl.loadClass(factory);
                return ReflectionUtils.newInstance(loaded, clazz);
            } catch (Throwable t) {
                LOGGER.trace("Exception while loading factory " + factory, t);
            }
        }

        ClassLoader clDefault = DefaultIoServiceFactoryFactory.class.getClassLoader();
        if (cl != clDefault) {
            try {
                Class<?> loaded = clDefault.loadClass(factory);
                return ReflectionUtils.newInstance(loaded, clazz);
            } catch (Throwable t) {
                LOGGER.trace("Exception while loading factory " + factory, t);
            }
        }
        throw new IllegalStateException("Unable to create instance of class " + factory);
    }

    private static final class LazyDefaultIoServiceFactoryFactoryHolder {
        private static final DefaultIoServiceFactoryFactory INSTANCE = new DefaultIoServiceFactoryFactory();

        private LazyDefaultIoServiceFactoryFactoryHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    @SuppressWarnings("synthetic-access")
    public static DefaultIoServiceFactoryFactory getDefaultIoServiceFactoryFactoryInstance() {
        return LazyDefaultIoServiceFactoryFactoryHolder.INSTANCE;
    }
}
