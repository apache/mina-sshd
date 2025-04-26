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

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.security.PrivilegedOperations;

/**
 * Default {@link ThreadFactory} used by {@link ThreadUtils} to create thread pools if user did provide one
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshdThreadFactory extends AbstractLoggingBean implements ThreadFactory {
    private final ThreadGroup group;
    private final AtomicInteger threadNumber = new AtomicInteger(1);
    private final String namePrefix;

    public SshdThreadFactory(String name) {
        ThreadGroup sg = PrivilegedOperations.getPrivilegedThreadGroup();
        group = (sg != null) ? sg : Thread.currentThread().getThreadGroup();
        String effectiveName = name.replace(' ', '-');
        namePrefix = "sshd-" + effectiveName + "-thread-";
    }

    @Override
    public Thread newThread(Runnable r) {
        Thread t;
        try {
            // see SSHD-668
            t = PrivilegedOperations.doPrivilegedConditional(() -> new Thread(
                    group, r, namePrefix + threadNumber.getAndIncrement(), 0));
        } catch (PrivilegedOperations.PrivilegeException e) {
            Throwable err = e.getCause();
            if (err instanceof RuntimeException) {
                throw (RuntimeException) err;
            }
            throw new IllegalStateException(err);
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
