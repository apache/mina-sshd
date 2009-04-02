/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.cipher;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * Base class for all Cipher implementations delegating to the JCE provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class BaseCipher implements Cipher {

    private final int ivsize;
    private final int bsize;
    private final String algorithm;
    private final String transformation;
    private javax.crypto.Cipher cipher;

    public BaseCipher(int ivsize, int bsize, String algorithm, String transformation) {
        this.ivsize = ivsize;
        this.bsize = bsize;
        this.algorithm = algorithm;
        this.transformation = transformation;
    }

    public int getIVSize() {
        return ivsize;
    }

    public int getBlockSize() {
        return bsize;
    }

    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        key = resize(key, bsize);
        iv = resize(iv, ivsize);
        try {
            cipher = SecurityUtils.getCipher(transformation);
            cipher.init((mode == Mode.Encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE),
                        new SecretKeySpec(key, algorithm),
                        new IvParameterSpec(iv));
        }
        catch (Exception e) {
            cipher = null;
            throw e;
        }
    }

    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        cipher.update(input, inputOffset, inputLen, input, inputOffset);
    }

    private static final byte[] resize(byte[] data, int size) {
        if (data.length > size) {
            byte[] tmp = new byte[size];
            System.arraycopy(data, 0, tmp, 0, size);
            data = tmp;
        }
        return data;
    }

}
