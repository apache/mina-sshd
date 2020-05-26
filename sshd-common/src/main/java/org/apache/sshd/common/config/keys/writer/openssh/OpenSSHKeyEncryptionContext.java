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

package org.apache.sshd.common.config.keys.writer.openssh;

import org.apache.sshd.common.config.keys.loader.PrivateKeyEncryptionContext;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A {@link PrivateKeyEncryptionContext} for use with a {@link OpenSSHKeyPairResourceWriter}.
 */
public class OpenSSHKeyEncryptionContext extends PrivateKeyEncryptionContext {

    /** Default number of bcrypt KDF rounds to apply. */
    public static final int DEFAULT_KDF_ROUNDS = 16;

    public static final String AES = "AES";

    private int kdfRounds = DEFAULT_KDF_ROUNDS;

    public OpenSSHKeyEncryptionContext() {
        setCipherMode("CTR"); // Set default to CTR, as in OpenSSH
    }

    @Override
    public String getCipherName() {
        return AES;
    }

    @Override
    public void setCipherName(String value) {
        ValidateUtils.checkTrue((value != null) && value.equalsIgnoreCase(AES),
                "OpenSSHKeyEncryptionContext works only with AES encryption");
    }

    /**
     * Retrieves the number of KDF rounds to apply.
     *
     * @return the default number of KDF rounds, >= {@link #DEFAULT_KDF_ROUNDS}
     */
    public int getKdfRounds() {
        return kdfRounds;
    }

    /**
     * Sets the number of KDF rounds to apply. If smaller than the {@link #DEFAULT_KDF_ROUNDS}, set that default.
     *
     * @param rounds number of rounds to apply
     */
    public void setKdfRounds(int rounds) {
        this.kdfRounds = Math.max(DEFAULT_KDF_ROUNDS, rounds);
    }

    /**
     * @return the cipher's factory name.
     */
    protected String getCipherFactoryName() {
        return getCipherName().toLowerCase() + getCipherType() + '-' + getCipherMode().toLowerCase();
    }
}
