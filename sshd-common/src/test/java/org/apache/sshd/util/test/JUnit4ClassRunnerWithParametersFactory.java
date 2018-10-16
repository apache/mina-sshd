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

import org.junit.runner.Runner;
import org.junit.runners.model.InitializationError;
import org.junit.runners.parameterized.ParametersRunnerFactory;
import org.junit.runners.parameterized.TestWithParameters;

/**
 * Avoids re-creating a test class instance for each parameterized test method. Usage:
 *
 * <PRE><code>
 * @FixMethodOrder(MethodSorters.NAME_ASCENDING)
 * @RunWith(Parameterized.class)
 * @UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
 * public class MyParameterizedTest {
 *      public MyParameterizedTest(...params...) {
 *          ....
 *      }
 *
 *      @Parameters(...)
 *      public static List<Object[]> parameters() {
 *          ...
 *      }
 * }
 * </code></PRE>
 *
 * @see JUnit4ClassRunnerWithParameters
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class JUnit4ClassRunnerWithParametersFactory implements ParametersRunnerFactory {
    public JUnit4ClassRunnerWithParametersFactory() {
        super();
    }

    @Override
    public Runner createRunnerForTestWithParameters(TestWithParameters test) throws InitializationError {
        return new JUnit4ClassRunnerWithParameters(test);
    }
}
