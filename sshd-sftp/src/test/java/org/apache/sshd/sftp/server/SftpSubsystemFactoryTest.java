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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SftpSubsystemFactoryTest extends JUnitTestSupport {
    public SftpSubsystemFactoryTest() {
        super();
    }

    /**
     * Make sure that the builder returns a factory with the default values if no {@code withXXX} method is invoked
     */
    @Test
    void builderDefaultFactoryValues() {
        SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder().build();
        assertNull(factory.resolveExecutorService(), "Mismatched executor");
        assertSame(SftpSubsystemFactory.DEFAULT_POLICY,
                factory.getUnsupportedAttributePolicy(),
                "Mismatched unsupported attribute policy");
    }

    /**
     * Make sure that the builder initializes correctly the built factory
     */
    @Test
    void builderCorrectlyInitializesFactory() {
        SftpSubsystemFactory.Builder builder = new SftpSubsystemFactory.Builder();
        CloseableExecutorService service = dummyExecutor();
        SftpSubsystemFactory factory = builder.withExecutorServiceProvider(() -> service)
                .build();
        assertSame(service, factory.resolveExecutorService(), "Mismatched executor");

        for (UnsupportedAttributePolicy policy : UnsupportedAttributePolicy.VALUES) {
            SftpSubsystemFactory actual = builder.withUnsupportedAttributePolicy(policy).build();
            assertSame(policy, actual.getUnsupportedAttributePolicy(), "Mismatched unsupported attribute policy");
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
    void builderUniqueInstance() {
        SftpSubsystemFactory.Builder builder = new SftpSubsystemFactory.Builder();
        CloseableExecutorService service1 = dummyExecutor();
        SftpSubsystemFactory f1 = builder.withExecutorServiceProvider(() -> service1).build();
        SftpSubsystemFactory f2 = builder.build();
        assertNotSame(f1, f2, "No new instance built");
        assertSame(f1.resolveExecutorService(), f2.resolveExecutorService(), "Mismatched executors");

        CloseableExecutorService service2 = dummyExecutor();
        SftpSubsystemFactory f3 = builder.withExecutorServiceProvider(() -> service2).build();
        assertNotSame(f1.resolveExecutorService(), f3.resolveExecutorService(), "Executor service not changed");
    }

    private static CloseableExecutorService dummyExecutor() {
        return Mockito.mock(CloseableExecutorService.class);
    }
}
