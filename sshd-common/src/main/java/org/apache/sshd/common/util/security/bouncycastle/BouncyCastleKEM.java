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
package org.apache.sshd.common.util.security.bouncycastle;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.apache.sshd.common.util.security.KEM;
import org.apache.sshd.common.util.security.KEMFactory;

enum BouncyCastleKEM implements KEMFactory {

    INSTANCE;

    @Override
    public KEM get(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        if (KEM.ML_KEM_768.equalsIgnoreCase(algorithm)) {
            return MLKEM.ML_KEM_768;
        } else if (KEM.ML_KEM_1024.equalsIgnoreCase(algorithm)) {
            return MLKEM.ML_KEM_1024;
        } else if (KEM.SNTRUP_761.equalsIgnoreCase(algorithm)) {
            return SNTRUP761.INSTANCE;
        }
        throw new NoSuchAlgorithmException("KEM '" + algorithm + "' unknown");
    }
}
