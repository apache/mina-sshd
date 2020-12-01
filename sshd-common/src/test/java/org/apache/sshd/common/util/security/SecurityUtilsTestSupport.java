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

package org.apache.sshd.common.util.security;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SecurityUtilsTestSupport extends JUnitTestSupport {
    public static final String BC_NAMED_USAGE_PROP = SecurityProviderRegistrar.CONFIG_PROP_BASE
                                                     + "." + SecurityUtils.BOUNCY_CASTLE
                                                     + "." + SecurityProviderRegistrar.NAMED_PROVIDER_PROPERTY;

    protected SecurityUtilsTestSupport() {
        super();
    }

    // NOTE: Using the BouncyCastle provider instead of the name does not work as expected so we take no chances
    @BeforeClass
    public static void useNamedBouncyCastleProvider() {
        System.setProperty(BC_NAMED_USAGE_PROP, Boolean.TRUE.toString());
    }

    @AfterClass
    public static void unsetBouncyCastleProviderUsagePreference() {
        System.clearProperty(BC_NAMED_USAGE_PROP);
    }
}
