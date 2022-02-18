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

package org.apache.sshd.putty;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PuttySpecialKeysTest extends AbstractPuttyTestSupport {
    public PuttySpecialKeysTest() {
        super();
    }

    @Test   // SSHD-1247
    public void testArgon2KeyDerivation() throws Exception {
        Assume.assumeTrue("BC provider available", SecurityUtils.isBouncyCastleRegistered());
        testDecodeSpecialEncryptedPuttyKeyFile("ssh-rsa", "argon2id", "123456");
    }

    protected KeyPair testDecodeSpecialEncryptedPuttyKeyFile(
            String keyType, String flavor, String password)
            throws IOException, GeneralSecurityException {
        return testDecodeEncryptedPuttyKeyFile(
                getClass().getSimpleName() + "-" + keyType
                                               + "-" + flavor + "-" + KeyPair.class.getSimpleName()
                                               + "-" + password + PuttyKeyPairResourceParser.PPK_FILE_SUFFIX,
                false, password, keyType);
    }
}
