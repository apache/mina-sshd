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
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

public class BaseCBCCipher extends BaseCipher {

    private byte[] lastEncryptedBlock;

    public BaseCBCCipher(int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation,
                         int blkSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        if (mode == Mode.Decrypt) {
            lastEncryptedBlock = Arrays.copyOfRange(input, inputOffset + inputLen - getCipherBlockSize(),
                    inputOffset + inputLen);
        }
        super.update(input, inputOffset, inputLen);
    }

    @Override
    protected AlgorithmParameterSpec determineNewParameters(byte[] processed, int offset, int length) {
        // The IV is the last encrypted block
        if (mode == Mode.Decrypt) {
            byte[] result = lastEncryptedBlock;
            lastEncryptedBlock = null;
            return new IvParameterSpec(result);
        }
        return new IvParameterSpec(Arrays.copyOfRange(processed, offset + length - getCipherBlockSize(), offset + length));
    }
}
