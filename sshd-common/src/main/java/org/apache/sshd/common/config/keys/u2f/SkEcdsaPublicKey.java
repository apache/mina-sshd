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
package org.apache.sshd.common.config.keys.u2f;

import java.security.interfaces.ECPublicKey;
import java.util.Objects;

import org.apache.sshd.common.config.keys.impl.SkECDSAPublicKeyEntryDecoder;

public class SkEcdsaPublicKey implements SecurityKeyPublicKey<ECPublicKey> {

    public static final String ALGORITHM = "ECDSA-SK";

    private static final long serialVersionUID = -8758432826838775097L;

    private final String appName;
    private final boolean noTouchRequired;
    private final boolean verifyRequired;
    private final ECPublicKey delegatePublicKey;

    /**
     * Creates a new instance.
     *
     * @param      appName           application name
     * @param      noTouchRequired   whether the "no-touch-required" flag was present in authorized_keys
     * @param      delegatePublicKey the underlying real public key
     * @deprecated                   use {@link #SkEcdsaPublicKey(String, boolean, boolean, ECPublicKey)} instead
     */
    @Deprecated
    public SkEcdsaPublicKey(String appName, boolean noTouchRequired, ECPublicKey delegatePublicKey) {
        this(appName, noTouchRequired, false, delegatePublicKey);
    }

    public SkEcdsaPublicKey(String appName, boolean noTouchRequired, boolean verifyRequired, ECPublicKey delegatePublicKey) {
        this.appName = appName;
        this.noTouchRequired = noTouchRequired;
        this.verifyRequired = verifyRequired;
        this.delegatePublicKey = delegatePublicKey;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getKeyType() {
        return SkECDSAPublicKeyEntryDecoder.KEY_TYPE;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String getAppName() {
        return appName;
    }

    @Override
    public boolean isNoTouchRequired() {
        return noTouchRequired;
    }

    @Override
    public boolean isVerifyRequired() {
        return verifyRequired;
    }

    @Override
    public ECPublicKey getDelegatePublicKey() {
        return delegatePublicKey;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[appName=" + getAppName()
               + ", noTouchRequired=" + isNoTouchRequired()
               + ", verifyRequired=" + isVerifyRequired()
               + ", delegatePublicKey=" + getDelegatePublicKey()
               + "]";
    }

    @Override
    public int hashCode() {
        return Objects.hash(appName, noTouchRequired, delegatePublicKey);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        SkEcdsaPublicKey other = (SkEcdsaPublicKey) obj;
        return Objects.equals(this.appName, other.appName)
                && this.noTouchRequired == other.noTouchRequired
                && Objects.equals(this.delegatePublicKey, other.delegatePublicKey);
    }
}
