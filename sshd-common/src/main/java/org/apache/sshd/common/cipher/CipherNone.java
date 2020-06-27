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
 * Represents a no-op cipher. This cipher can not really be used during authentication and should only be used after, so
 * that authentication remains secured, but not the remaining of the exchanges.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CipherNone implements Cipher {
    public CipherNone() {
        super();
    }

    @Override
    public String getAlgorithm() {
        return "none";
    }

    @Override
    public int getKeySize() {
        return 0;
    }

    @Override
    public String getTransformation() {
        return "none";
    }

    @Override
    public int getIVSize() {
        return 8; // dummy - not zero in order to avoid some code that uses it as divisor
    }

    @Override
    public int getAuthenticationTagSize() {
        return 0;
    }

    @Override
    public int getKdfSize() {
        return 16; // dummy - not zero in order to avoid some code that uses it as divisor
    }

    @Override
    public int getCipherBlockSize() {
        return 8; // dummy - not zero in order to avoid some code that uses it as divisor
    }

    @Override
    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        // ignored - always succeeds
    }

    @Override
    public void updateAAD(byte[] data, int offset, int length) throws Exception {
        // ignored - always succeeds
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        // ignored - always succeeds
    }
}
