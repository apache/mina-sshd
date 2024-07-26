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
package org.apache.sshd.common.random;

import java.util.Collection;
import java.util.LinkedList;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class RandomFactoryTest extends JUnitTestSupport {
    private RandomFactory factory;

    public void initRandomFactoryTest(RandomFactory factory) {
        this.factory = factory;
    }

    public static Collection<Object[]> parameters() {
        Collection<RandomFactory> testCases = new LinkedList<>();
        testCases.add(JceRandomFactory.INSTANCE);
        if (SecurityUtils.isBouncyCastleRegistered()) {
            testCases.add(SecurityUtils.getRandomFactory());
        } else {
            System.out.println("Skip BouncyCastleRandomFactory - unsupported");
        }

        return parameterize(testCases);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}")
    public void randomFactory(RandomFactory factory) {
        initRandomFactoryTest(factory);
        Assumptions.assumeTrue(factory.isSupported(), "Skip unsupported factory: " + factory.getName());
        long t = testRandom(factory.create());
        System.out.println(factory.getName() + " duration: " + t + " " + TimeUnit.MICROSECONDS);
    }

    // returns duration in microseconds
    private static long testRandom(Random random) {
        byte[] bytes = new byte[32];
        long l0 = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            random.fill(bytes, 8, 16);
        }
        long l1 = System.nanoTime();
        return TimeUnit.NANOSECONDS.toMicros(l1 - l0);
    }
}
