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

import org.junit.runners.model.InitializationError;
import org.junit.runners.parameterized.BlockJUnit4ClassRunnerWithParameters;
import org.junit.runners.parameterized.TestWithParameters;

/**
 * Uses a cached created instance instead of a new one on every call of {@code #createTest()}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class JUnit4ClassRunnerWithParameters extends BlockJUnit4ClassRunnerWithParameters {
    private volatile Object testInstance;

    public JUnit4ClassRunnerWithParameters(TestWithParameters test) throws InitializationError {
        super(test);
    }

    @Override
    public Object createTest() throws Exception {
        synchronized (this) {
            if (testInstance == null) {
                testInstance = super.createTest();
            }
        }

        return testInstance;
    }
}
