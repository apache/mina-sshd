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

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class ExceptionUtilsAndroidPeelTest extends JUnitTestSupport {
    private boolean androidMode;

    public void initExceptionUtilsAndroidPeelTest(boolean androidMode) {
        this.androidMode = androidMode;
    }

    public static List<Object[]> parameters() {
        return Stream.of(Boolean.TRUE, Boolean.FALSE).map(v -> new Object[] { v }).collect(Collectors.toList());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "android={0}")
    public void peelJavaxManagementException(boolean androidMode) {
        initExceptionUtilsAndroidPeelTest(androidMode);
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
