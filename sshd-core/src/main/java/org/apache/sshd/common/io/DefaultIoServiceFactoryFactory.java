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

import java.util.Iterator;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultIoServiceFactoryFactory extends AbstractIoServiceFactoryFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultIoServiceFactoryFactory.class);

    private IoServiceFactoryFactory factory;

    protected DefaultIoServiceFactoryFactory() {
        this(null, true);
    }

    protected DefaultIoServiceFactoryFactory(ExecutorService executors, boolean shutdownOnExit) {
        super(executors, shutdownOnExit);
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
            if (factory == null) {
                factory = newInstance(IoServiceFactoryFactory.class);
                if (factory instanceof ExecutorServiceConfigurer) {
                    ExecutorServiceConfigurer configurer = (ExecutorServiceConfigurer) factory;
                    configurer.setExecutorService(getExecutorService());
                    configurer.setShutdownOnExit(isShutdownOnExit());
                }
            }
        }
        return factory;
    }

    public static <T extends IoServiceFactoryFactory> T newInstance(Class<T> clazz) {
        String factory = System.getProperty(clazz.getName());
        if (!GenericUtils.isEmpty(factory)) {
            return newInstance(clazz, factory);
        }

        Thread currentThread = Thread.currentThread();
        ClassLoader cl = currentThread.getContextClassLoader();
        if (cl != null) {
            T t = tryLoad(ServiceLoader.load(clazz, cl));
            if (t != null) {
                return t;
            }
        }

        ClassLoader clDefault = DefaultIoServiceFactoryFactory.class.getClassLoader();
        if (cl != clDefault) {
            T t = tryLoad(ServiceLoader.load(clazz, clDefault));
            if (t != null) {
                return t;
            }
        }
        throw new IllegalStateException("Could not find a valid sshd io provider");
    }

    public static <T extends IoServiceFactoryFactory> T tryLoad(ServiceLoader<T> loader) {
        Iterator<T> it = loader.iterator();
        try {
            while (it.hasNext()) {
                try {
                    return it.next();
                } catch (Throwable t) {
                    LOGGER.trace("Exception while loading factory from ServiceLoader", t);
                }
            }
        } catch (Throwable t) {
            LOGGER.trace("Exception while loading factory from ServiceLoader", t);
        }
        return null;
    }

    public static <T extends IoServiceFactoryFactory> T newInstance(Class<T> clazz, String factory) {
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
                Object factoryInstance = loaded.newInstance();
                return clazz.cast(factoryInstance);
            } catch (Throwable t) {
                LOGGER.trace("Exception while loading factory " + factory, t);
            }
        }

        ClassLoader clDefault = DefaultIoServiceFactoryFactory.class.getClassLoader();
        if (cl != clDefault) {
            try {
                Class<?> loaded = clDefault.loadClass(factory);
                Object factoryInstance = loaded.newInstance();
                return clazz.cast(factoryInstance);
            } catch (Throwable t) {
                LOGGER.trace("Exception while loading factory " + factory, t);
            }
        }
        throw new IllegalStateException("Unable to create instance of class " + factory);
    }

    private static class LazyDefaultIoServiceFactoryFactoryHolder {
        private static final DefaultIoServiceFactoryFactory INSTANCE = new DefaultIoServiceFactoryFactory();
    }

    @SuppressWarnings("synthetic-access")
    public static DefaultIoServiceFactoryFactory getDefaultIoServiceFactoryFactoryInstance() {
        return LazyDefaultIoServiceFactoryFactoryHolder.INSTANCE;
    }
}
