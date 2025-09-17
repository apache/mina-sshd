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

/**
 * Abstract super class for ChaCha20-Poly1305 implementations.
 */
public abstract class AbstractChaCha20Cipher implements Cipher {

    protected AbstractChaCha20Cipher() {
        super();
    }

    @Override
    public String getAlgorithm() {
        return "ChaCha20";
    }

    @Override
    public String getTransformation() {
        return "ChaCha20";
    }

    @Override
    public int getIVSize() {
        return 8;
    }

    @Override
    public int getAuthenticationTagSize() {
        return 16;
    }

    @Override
    public int getCipherBlockSize() {
        return 8;
    }

    @Override
    public int getKdfSize() {
        return 64;
    }

    @Override
    public int getKeySize() {
        return 512;
    }

    @Override
    public String toString() {
        return "chacha20-poly1305";
    }
}
