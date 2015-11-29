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
package org.apache.sshd.common.cipher;

import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.util.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BaseRC4Cipher extends BaseCipher {

    public static final int SKIP_SIZE = 1536;

    public BaseRC4Cipher(int ivsize, int bsize) {
        super(ivsize, bsize, "ARCFOUR", "RC4");
    }

    @Override
    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        key = resize(key, getBlockSize());
        try {
            cipher = SecurityUtils.getCipher(getTransformation());
            cipher.init(Mode.Encrypt.equals(mode)  ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, getAlgorithm()));

            byte[] foo = new byte[1];
            for (int i = 0; i < SKIP_SIZE; i++) {
                cipher.update(foo, 0, 1, foo, 0);
            }
        } catch (Exception e) {
            cipher = null;
            throw e;
        }
    }

}
