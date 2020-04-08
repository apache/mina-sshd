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
package org.apache.sshd.util.test;

import java.time.Duration;
import java.util.Collection;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * Helper used as base class for all test classes
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class BaseTestSupport extends JUnitTestSupport {
    // can be used to override the 'localhost' with an address other than 127.0.0.1 in case it is required
    public static final String TEST_LOCALHOST =
        System.getProperty("org.apache.sshd.test.localhost", SshdSocketAddress.LOCALHOST_IPV4);

    public static final Duration CONNECT_TIMEOUT = getTimeout("connect", Duration.ofSeconds(7));
    public static final Duration AUTH_TIMEOUT = getTimeout("auth", Duration.ofSeconds(5));
    public static final Duration OPEN_TIMEOUT = getTimeout("open", Duration.ofSeconds(9));
    public static final Duration DEFAULT_TIMEOUT = getTimeout("default", Duration.ofSeconds(5));
    public static final Duration CLOSE_TIMEOUT = getTimeout("close", Duration.ofSeconds(15));

    @Rule
    public final TestWatcher rule = new TestWatcher() {
        // TODO consider using a ThreadLocal storage for the start time - provided
        //      the code is assured to call starting/finished on the same thread
        private long startTime;

        @Override
        protected void starting(Description description) {
            System.out.append(System.lineSeparator())
                .append("Starting ").append(description.getClassName())
                .append(':').append(description.getMethodName())
                .println("...");
            try {
                IoServiceFactoryFactory ioProvider = getIoServiceProvider();
                System.out.println("Using default provider: " + ioProvider.getClass().getName());
            } catch (Throwable t) {
                // Ignore
            }
            System.out.println();
            startTime = System.currentTimeMillis();
        }

        @Override
        protected void finished(Description description) {
            long duration = System.currentTimeMillis() - startTime;
            System.out.append(System.lineSeparator())
                .append("Finished ").append(description.getClassName())
                .append(':').append(description.getMethodName())
                .append(" in ").append(Long.toString(duration))
                .println(" ms");
        }
    };

    protected BaseTestSupport() {
        super();
    }

    @BeforeClass
    public static void setupRootLoggerLevel() {
        String levelName = System.getProperty(
            "org.apache.sshd.test.root.log.level", org.apache.log4j.Level.INFO.toString());
        org.apache.log4j.Level level = org.apache.log4j.Level.toLevel(
            levelName.toUpperCase(), org.apache.log4j.Level.INFO);
        org.apache.log4j.Logger logger = org.apache.log4j.Logger.getRootLogger();
        logger.setLevel(level);
    }

    public static Duration getTimeout(String property, Duration defaultValue) {
        // Do we have a specific timeout value ?
        String str = System.getProperty("org.apache.sshd.test.timeout." + property);
        if (GenericUtils.isNotEmpty(str)) {
            return Duration.ofMillis(Long.parseLong(str));
        }

        // Do we have a specific factor ?
        str = System.getProperty("org.apache.sshd.test.timeout.factor." + property);
        if (GenericUtils.isEmpty(str)) {
            // Do we have a global factor ?
            str = System.getProperty("org.apache.sshd.test.timeout.factor");
        }

        if (GenericUtils.isNotEmpty(str)) {
            double factor = Double.parseDouble(str);
            long dur = Math.round(defaultValue.toMillis() * factor);
            return Duration.ofMillis(dur);
        }

        return defaultValue;
    }

    protected SshServer setupTestServer() {
        return CoreTestSupportUtils.setupTestServer(getClass());
    }

    protected SshClient setupTestClient() {
        return CoreTestSupportUtils.setupTestClient(getClass());
    }

    protected void assumeNotIoServiceProvider(
            Collection<BuiltinIoServiceFactoryFactories> excluded) {
        assumeNotIoServiceProvider(getCurrentTestName(), excluded);
    }

    public static IoServiceFactoryFactory getIoServiceProvider() {
        DefaultIoServiceFactoryFactory factory =
            DefaultIoServiceFactoryFactory.getDefaultIoServiceFactoryFactoryInstance();
        return factory.getIoServiceProvider();
    }

    public static void assumeNotIoServiceProvider(
            String message, Collection<BuiltinIoServiceFactoryFactories> excluded) {
        if (GenericUtils.isEmpty(excluded)) {
            return;
        }

        assumeNotIoServiceProvider(message, getIoServiceProvider(), excluded);
    }

    public static void assumeNotIoServiceProvider(
            String message, AbstractFactoryManager manager,
            Collection<BuiltinIoServiceFactoryFactories> excluded) {
        assumeNotIoServiceProvider(message, manager.getIoServiceFactoryFactory(), excluded);
    }

    public static void assumeNotIoServiceProvider(
            String message, IoServiceFactoryFactory provider,
            Collection<BuiltinIoServiceFactoryFactories> excluded) {
        if (GenericUtils.isEmpty(excluded)) {
            return;
        }

        Class<?> clazz = provider.getClass();
        String clazzName = clazz.getName();
        BuiltinIoServiceFactoryFactories match = excluded.stream()
            .filter(f -> clazzName.equals(f.getFactoryClassName()))
            .findFirst()
            .orElse(null);
        Assume.assumeTrue(message + " - skip factory=" + match, match == null);
    }
}
