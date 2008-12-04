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
package org.apache.sshd.common;

public interface Cipher  {

    enum Mode {
        Encrypt, Decrypt
    }

    /**
     * Retrieves the size of the initialization vector
     *
     * @return
     */
    int getIVSize();

    /**
     * Retrieves the block size for this cipher
     *
     * @return
     */
    int getBlockSize();

    /**
     * Initialize the cipher for encryption or decryption with
     * the given private key and initialization vector
     *
     * @param mode
     * @param key
     * @param iv
     * @throws Exception
     */
    void init(Mode mode, byte[] key, byte[] iv) throws Exception;

    /**
     * Performs in-place encryption or decryption on the given data.
     * 
     * @param input
     * @param inputOffset
     * @param inputLen
     * @throws Exception
     */
    void update(byte[] input, int inputOffset, int inputLen) throws Exception;

}