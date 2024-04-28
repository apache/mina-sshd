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

import java.util.Objects;

import net.i2p.crypto.eddsa.EdDSAPublicKey;

public class SkED25519PublicKey implements SecurityKeyPublicKey<EdDSAPublicKey> {

    public static final String ALGORITHM = "ED25519-SK";

    private static final long serialVersionUID = 4587115316266869640L;

    private final String appName;
    private final boolean noTouchRequired;
    private final EdDSAPublicKey delegatePublicKey;

    public SkED25519PublicKey(String appName, boolean noTouchRequired, EdDSAPublicKey delegatePublicKey) {
        this.appName = appName;
        this.noTouchRequired = noTouchRequired;
        this.delegatePublicKey = delegatePublicKey;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
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
    public EdDSAPublicKey getDelegatePublicKey() {
        return delegatePublicKey;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[appName=" + getAppName()
               + ", noTouchRequired=" + isNoTouchRequired()
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

        SkED25519PublicKey other = (SkED25519PublicKey) obj;
        return Objects.equals(this.appName, other.appName)
                && this.noTouchRequired == other.noTouchRequired
                && Objects.equals(this.delegatePublicKey, other.delegatePublicKey);
    }
}
