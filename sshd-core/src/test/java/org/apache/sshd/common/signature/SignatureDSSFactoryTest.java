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

package org.apache.sshd.common.signature;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.DSSPublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class SignatureDSSFactoryTest extends AbstractSignatureFactoryTestSupport {
    private static final List<NamedFactory<Signature>> FACTORIES =
            Collections.unmodifiableList(Collections.<NamedFactory<Signature>>singletonList(BuiltinSignatures.dsa));

    public SignatureDSSFactoryTest(int keySize) {
        super(KeyPairProvider.SSH_DSS, keySize);
    }

    @Parameters(name = "keySize={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(DSS_SIZES);
    }

    @Test
    public void testDSSPublicKeyAuth() throws Exception {
        testKeyPairProvider(DSSPublicKeyEntryDecoder.INSTANCE, FACTORIES);
    }
}
