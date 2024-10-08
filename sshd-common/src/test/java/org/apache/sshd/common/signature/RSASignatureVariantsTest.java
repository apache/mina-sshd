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

import java.security.KeyPair;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * NOTE: some tests are inherited from parent
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class RSASignatureVariantsTest extends SignatureVariantTestSupport {
    private static KeyPair kp;

    @ParameterizedTest
    @EnumSource(value = BuiltinSignatures.class, names = { "rsa", "rsaSHA256", "rsaSHA512" })
    public void initRSASignatureVariantsTest(SignatureFactory factory) throws Exception {
        signature(factory, kp);
    }

    @BeforeAll
    static void initializeSigningKeyPair() throws Exception {
        kp = initializeSigningKeyPair(KeyUtils.RSA_ALGORITHM);
    }

}
