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

import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
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
    public static final String TEST_LOCALHOST = System.getProperty("org.apache.sshd.test.localhost", SshdSocketAddress.LOCALHOST_IPV4);

    @Rule
    public final TestWatcher rule = new TestWatcher() {
        // TODO consider using a ThreadLocal storage for the start time - provided
        //      the code is assured to call starting/finished on the same thread
        private long startTime;

        @Override
        protected void starting(Description description) {
            System.out.println("\nStarting " + description.getClassName() + ":" + description.getMethodName() + "...");
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
            System.out.println("\nFinished " + description.getClassName() + ":" + description.getMethodName() + " in " + duration + " ms\n");
        }
    };

    protected BaseTestSupport() {
        super();
    }

    protected SshServer setupTestServer() {
        return CoreTestSupportUtils.setupTestServer(getClass());
    }

    protected SshClient setupTestClient() {
        return CoreTestSupportUtils.setupTestClient(getClass());
    }

    public static IoServiceFactoryFactory getIoServiceProvider() {
        DefaultIoServiceFactoryFactory factory =
            DefaultIoServiceFactoryFactory.getDefaultIoServiceFactoryFactoryInstance();
        return factory.getIoServiceProvider();
    }
}
