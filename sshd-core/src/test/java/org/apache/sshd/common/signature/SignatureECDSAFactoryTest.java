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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.ECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.util.SecurityUtils;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Makes sure that all the available {@link Signature} implementations are tested
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class SignatureECDSAFactoryTest extends AbstractSignatureFactoryTestSupport {
    private static final List<NamedFactory<Signature>> FACTORIES =
            Collections.unmodifiableList(
                    Arrays.<NamedFactory<Signature>>asList(
                            BuiltinSignatures.nistp256,
                            BuiltinSignatures.nistp384,
                            BuiltinSignatures.nistp521
                    ));

    public SignatureECDSAFactoryTest(ECCurves curve) {
        super(curve.getName(), curve.getKeySize());
    }

    @Parameters(name = "keySize={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(ECCurves.VALUES);
    }

    @Test
    public void testECDSAPublicKeyAuth() throws Exception {
        Assume.assumeTrue("ECC not supported", SecurityUtils.hasEcc());
        testKeyPairProvider(ECDSAPublicKeyEntryDecoder.INSTANCE, FACTORIES);
    }
}
