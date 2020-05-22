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

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

public class BaseGCMCipher extends BaseAEADCipher {

    public BaseGCMCipher(
                         int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation,
                         int blkSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    protected AlgorithmParameterSpec initializeAlgorithmParameters(byte[] iv) {
        Buffer buffer = new ByteArrayBuffer(iv);
        buffer.rpos(Integer.BYTES);
        long ic = buffer.getLong();
        // decrement IV as it will be incremented back to initial value on first call to updateWithAAD
        ic = (ic - 1) & 0x0ffffffffL;
        buffer.wpos(Integer.BYTES);
        buffer.putLong(ic);
        return new GCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, buffer.array());
    }

    @Override
    protected AlgorithmParameterSpec getNextAlgorithmParameters() {
        Cipher cipher = getCipherInstance();
        Buffer iv = new ByteArrayBuffer(cipher.getIV());
        iv.rpos(Integer.BYTES);
        long ic = iv.getLong();
        ic = (ic + 1) & 0x0ffffffffL;
        iv.wpos(Integer.BYTES);
        iv.putLong(ic);
        return new GCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, iv.array());
    }

}
