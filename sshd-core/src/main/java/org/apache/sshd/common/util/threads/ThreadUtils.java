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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.util.logging.AbstractLoggingBean;

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
     * Wraps an {@link ExecutorService} in such a way as to &quot;protect&quot;
     * it for calls to the {@link ExecutorService#shutdown()} or
     * {@link ExecutorService#shutdownNow()}. All other calls are delegated as-is
     * to the original service. <B>Note:</B> the exposed wrapped proxy will
     * answer correctly the {@link ExecutorService#isShutdown()} query if indeed
     * one of the {@code shutdown} methods was invoked.
     *
     * @param executorService The original service - ignored if {@code null}
     * @param shutdownOnExit  If {@code true} then it is OK to shutdown the executor
     *                        so no wrapping takes place.
     * @return Either the original service or a wrapped one - depending on the
     * value of the <tt>shutdownOnExit</tt> parameter
     */
    public static ExecutorService protectExecutorServiceShutdown(final ExecutorService executorService, boolean shutdownOnExit) {
        if (executorService == null || shutdownOnExit) {
            return executorService;
        } else {
            return (ExecutorService) Proxy.newProxyInstance(
                    resolveDefaultClassLoader(executorService),
                    new Class<?>[]{ExecutorService.class},
                    new InvocationHandler() {
                        private final AtomicBoolean stopped = new AtomicBoolean(false);

                        @Override
                        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                            String name = method.getName();
                            if ("isShutdown".equals(name)) {
                                return stopped.get();
                            } else if ("shutdown".equals(name)) {
                                stopped.set(true);
                                return null;    // void...
                            } else if ("shutdownNow".equals(name)) {
                                stopped.set(true);
                                return Collections.emptyList();
                            } else {
                                return method.invoke(executorService, args);
                            }
                        }
                    });
        }
    }

    public static ClassLoader resolveDefaultClassLoader(Object anchor) {
        return resolveDefaultClassLoader(anchor == null ? null : anchor.getClass());
    }

    /**
     * <P>Attempts to find the most suitable {@link ClassLoader} as follows:</P>
     * <UL>
     * <LI><P>
     * Check the {@link Thread#getContextClassLoader()} value
     * </P></LI>
     *
     * <LI><P>
     * If no thread context class loader then check the anchor
     * class (if given) for its class loader
     * </P></LI>
     *
     * <LI><P>
     * If still no loader available, then use {@link ClassLoader#getSystemClassLoader()}
     * </P></LI>
     * </UL>
     *
     * @param anchor The anchor {@link Class} to use if no current thread
     *               - ignored if {@code null}
     *               context class loader
     * @return The resolver {@link ClassLoader}
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

        if (cl == null) {   // can happen for core Java classes
            cl = ClassLoader.getSystemClassLoader();
        }

        return cl;
    }

    public static ExecutorService newFixedThreadPool(String poolName, int nThreads) {
        return new ThreadPoolExecutor(nThreads, nThreads,
                0L, TimeUnit.MILLISECONDS, // TODO make this configurable
                new LinkedBlockingQueue<Runnable>(),
                new SshdThreadFactory(poolName),
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public static ExecutorService newCachedThreadPool(String poolName) {
        return new ThreadPoolExecutor(0, Integer.MAX_VALUE, // TODO make this configurable
                60L, TimeUnit.SECONDS, // TODO make this configurable
                new SynchronousQueue<Runnable>(),
                new SshdThreadFactory(poolName),
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public static ScheduledExecutorService newSingleThreadScheduledExecutor(String poolName) {
        return new ScheduledThreadPoolExecutor(1, new SshdThreadFactory(poolName));
    }

    public static ExecutorService newSingleThreadExecutor(String poolName) {
        return newFixedThreadPool(poolName, 1);
    }

    public static class SshdThreadFactory extends AbstractLoggingBean implements ThreadFactory {
        private final ThreadGroup group;
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;

        public SshdThreadFactory(String name) {
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
            String effectiveName = name.replace(' ', '-');
            namePrefix = "sshd-" + effectiveName + "-thread-";
        }

        @Override
        public Thread newThread(final Runnable r) {
            Thread t;
            try {
                // see SSHD-668
                t = AccessController.doPrivileged(new PrivilegedExceptionAction<Thread>() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public Thread run() {
                        return new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
                    }
                });
            } catch (PrivilegedActionException e) {
                Exception err = e.getException();
                if (err instanceof RuntimeException) {
                    throw (RuntimeException) err;
                } else {
                    throw new RuntimeException(err);
                }
            }

            if (!t.isDaemon()) {
                t.setDaemon(true);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            if (log.isTraceEnabled()) {
                log.trace("newThread({})[{}] runnable={}", group, t.getName(), r);
            }
            return t;
        }
    }
}
