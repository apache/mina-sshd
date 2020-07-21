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

package org.apache.sshd.sftp.server;

import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class SftpSubsystemFactoryTest extends JUnitTestSupport {
    public SftpSubsystemFactoryTest() {
        super();
    }

    /**
     * Make sure that the builder returns a factory with the default values if no {@code withXXX} method is invoked
     */
    @Test
    public void testBuilderDefaultFactoryValues() {
        SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder().build();
        assertNull("Mismatched executor", factory.resolveExecutorService());
        assertSame("Mismatched unsupported attribute policy", SftpSubsystemFactory.DEFAULT_POLICY,
                factory.getUnsupportedAttributePolicy());
    }

    /**
     * Make sure that the builder initializes correctly the built factory
     */
    @Test
    public void testBuilderCorrectlyInitializesFactory() {
        SftpSubsystemFactory.Builder builder = new SftpSubsystemFactory.Builder();
        CloseableExecutorService service = dummyExecutor();
        SftpSubsystemFactory factory = builder.withExecutorServiceProvider(() -> service)
                .build();
        assertSame("Mismatched executor", service, factory.resolveExecutorService());

        for (UnsupportedAttributePolicy policy : UnsupportedAttributePolicy.VALUES) {
            SftpSubsystemFactory actual = builder.withUnsupportedAttributePolicy(policy).build();
            assertSame("Mismatched unsupported attribute policy", policy, actual.getUnsupportedAttributePolicy());
        }
    }

    /**
     * <UL>
     * <LI>Make sure the builder returns new instances on every call to {@link SftpSubsystemFactory.Builder#build()}
     * method</LI>
     *
     * <LI>Make sure values are preserved between successive invocations of the
     * {@link SftpSubsystemFactory.Builder#build()} method</LI> </UL
     */
    @Test
    public void testBuilderUniqueInstance() {
        SftpSubsystemFactory.Builder builder = new SftpSubsystemFactory.Builder();
        CloseableExecutorService service1 = dummyExecutor();
        SftpSubsystemFactory f1 = builder.withExecutorServiceProvider(() -> service1).build();
        SftpSubsystemFactory f2 = builder.build();
        assertNotSame("No new instance built", f1, f2);
        assertSame("Mismatched executors", f1.resolveExecutorService(), f2.resolveExecutorService());

        CloseableExecutorService service2 = dummyExecutor();
        SftpSubsystemFactory f3 = builder.withExecutorServiceProvider(() -> service2).build();
        assertNotSame("Executor service not changed", f1.resolveExecutorService(), f3.resolveExecutorService());
    }

    private static CloseableExecutorService dummyExecutor() {
        return Mockito.mock(CloseableExecutorService.class);
    }
}
