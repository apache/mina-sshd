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

package org.apache.sshd.common.util;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.management.ReflectionException;

import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class ExceptionUtilsAndroidPeelTest extends JUnitTestSupport {
    private final boolean androidMode;

    public ExceptionUtilsAndroidPeelTest(boolean androidMode) {
        this.androidMode = androidMode;
    }

    @Parameters(name = "android={0}")
    public static List<Object[]> parameters() {
        return Stream.of(Boolean.TRUE, Boolean.FALSE).map(v -> new Object[] { v }).collect(Collectors.toList());
    }

    @Test
    public void testPeelJavaxManagementException() {
        try {
            OsUtils.setAndroid(androidMode);

            Exception original = new UnsupportedOperationException(getCurrentTestName() + "-wrapped");
            Throwable wrapper = new ReflectionException(original, original.getMessage() + "-wrapper");
            Throwable peeled = ExceptionUtils.peelException(wrapper);
            if (androidMode) {
                assertSame(wrapper, peeled);
            } else {
                assertSame(original, peeled);
            }
        } finally {
            OsUtils.setAndroid(null);    // restore auto-detection
        }
    }
}
