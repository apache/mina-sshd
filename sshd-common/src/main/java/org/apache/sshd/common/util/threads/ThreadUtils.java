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
package org.apache.sshd.common.util.threads;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.apache.sshd.common.util.ReflectionUtils;

/**
 * Utility class for thread pools.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class ThreadUtils {
    private ThreadUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * Wraps an {@link CloseableExecutorService} in such a way as to &quot;protect&quot; it for calls to the
     * {@link CloseableExecutorService#shutdown()} or {@link CloseableExecutorService#shutdownNow()}. All other calls
     * are delegated as-is to the original service. <B>Note:</B> the exposed wrapped proxy will answer correctly the
     * {@link CloseableExecutorService#isShutdown()} query if indeed one of the {@code shutdown} methods was invoked.
     *
     * @param  executorService The original service - ignored if {@code null}
     * @param  shutdownOnExit  If {@code true} then it is OK to shutdown the executor so no wrapping takes place.
     * @return                 Either the original service or a wrapped one - depending on the value of the
     *                         <tt>shutdownOnExit</tt> parameter
     */
    public static CloseableExecutorService protectExecutorServiceShutdown(
            CloseableExecutorService executorService, boolean shutdownOnExit) {
        if (executorService == null || shutdownOnExit || executorService instanceof NoCloseExecutor) {
            return executorService;
        } else {
            return new NoCloseExecutor(executorService);
        }
    }

    public static CloseableExecutorService noClose(CloseableExecutorService executorService) {
        return protectExecutorServiceShutdown(executorService, false);
    }

    public static ClassLoader resolveDefaultClassLoader(Object anchor) {
        return resolveDefaultClassLoader((anchor == null) ? null : anchor.getClass());
    }

    public static Iterable<ClassLoader> resolveDefaultClassLoaders(Object anchor) {
        return resolveDefaultClassLoaders((anchor == null) ? null : anchor.getClass());
    }

    public static Iterable<ClassLoader> resolveDefaultClassLoaders(Class<?> anchor) {
        return () -> iterateDefaultClassLoaders(anchor);
    }

    public static <T> T createDefaultInstance(
            Class<?> anchor, Class<? extends T> targetType, String className)
            throws ReflectiveOperationException {
        return createDefaultInstance(resolveDefaultClassLoaders(anchor), targetType, className);
    }

    public static <T> T createDefaultInstance(
            ClassLoader cl, Class<? extends T> targetType, String className)
            throws ReflectiveOperationException {
        Class<?> instanceType = cl.loadClass(className);
        return ReflectionUtils.newInstance(instanceType, targetType);
    }

    public static <T> T createDefaultInstance(
            Iterable<? extends ClassLoader> cls, Class<? extends T> targetType, String className)
            throws ReflectiveOperationException {
        for (ClassLoader cl : cls) {
            try {
                return createDefaultInstance(cl, targetType, className);
            } catch (ClassNotFoundException e) {
                // Ignore
            }
        }
        throw new ClassNotFoundException(className);
    }

    /**
     * <P>
     * Attempts to find the most suitable {@link ClassLoader} as follows:
     * </P>
     * <UL>
     * <LI>
     * <P>
     * Check the {@link Thread#getContextClassLoader()} value
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * If no thread context class loader then check the anchor class (if given) for its class loader
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * If still no loader available, then use {@link ClassLoader#getSystemClassLoader()}
     * </P>
     * </LI>
     * </UL>
     *
     * @param  anchor The anchor {@link Class} to use if no current thread context class loader - ignored if
     *                {@code null}
     *
     * @return        The resolved {@link ClassLoader} - <B>Note:</B> might still be {@code null} if went all the way
     *                &quot;down&quot; to the system class loader and it was also {@code null}.
     */
    public static ClassLoader resolveDefaultClassLoader(Class<?> anchor) {
        Thread thread = Thread.currentThread();
        ClassLoader cl = thread.getContextClassLoader();
        if (cl != null) {
            return cl;
        }

        if (anchor != null) {
            cl = anchor.getClassLoader();
        }

        if (cl == null) { // can happen for core Java classes
            cl = ClassLoader.getSystemClassLoader();
        }

        return cl;
    }

    public static Iterator<ClassLoader> iterateDefaultClassLoaders(Class<?> anchor) {
        Class<?> effectiveAnchor = (anchor == null) ? ThreadUtils.class : anchor;
        return new Iterator<ClassLoader>() {
            @SuppressWarnings({ "unchecked", "checkstyle:Indentation" })
            private final Supplier<? extends ClassLoader>[] suppliers = new Supplier[] {
                    () -> {
                        Thread thread = Thread.currentThread();
                        return thread.getContextClassLoader();
                    },
                    () -> effectiveAnchor.getClassLoader(),
                    ClassLoader::getSystemClassLoader
            };

            private int index;

            @Override
            public boolean hasNext() {
                for (; index < suppliers.length; index++) {
                    Supplier<? extends ClassLoader> scl = suppliers[index];
                    ClassLoader cl = scl.get();
                    if (cl != null) {
                        return true;
                    }
                }

                return false;
            }

            @Override
            public ClassLoader next() {
                if (index >= suppliers.length) {
                    throw new NoSuchElementException("All elements exhausted");
                }

                Supplier<? extends ClassLoader> scl = suppliers[index];
                index++;
                return scl.get();
            }
        };
    }

    public static CloseableExecutorService newFixedThreadPoolIf(
            CloseableExecutorService executorService, String poolName, int nThreads) {
        return executorService == null ? newFixedThreadPool(poolName, nThreads) : executorService;
    }

    public static CloseableExecutorService newFixedThreadPool(String poolName, int nThreads) {
        return new SshThreadPoolExecutor(
                nThreads, nThreads,
                0L, TimeUnit.MILLISECONDS, // TODO make this configurable
                new LinkedBlockingQueue<>(),
                new SshdThreadFactory(poolName),
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public static CloseableExecutorService newCachedThreadPoolIf(
            CloseableExecutorService executorService, String poolName) {
        return executorService == null ? newCachedThreadPool(poolName) : executorService;
    }

    public static CloseableExecutorService newCachedThreadPool(String poolName) {
        return new SshThreadPoolExecutor(
                0, Integer.MAX_VALUE, // TODO make this configurable
                60L, TimeUnit.SECONDS, // TODO make this configurable
                new SynchronousQueue<>(),
                new SshdThreadFactory(poolName),
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public static ScheduledExecutorService newSingleThreadScheduledExecutor(String poolName) {
        return new ScheduledThreadPoolExecutor(1, new SshdThreadFactory(poolName));
    }

    public static CloseableExecutorService newSingleThreadExecutor(String poolName) {
        return newFixedThreadPool(poolName, 1);
    }
}
