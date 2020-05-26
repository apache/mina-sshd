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
package org.apache.sshd.common.u2f;

import java.security.interfaces.ECPublicKey;

public class SkEcdsaPublicKey implements SecurityKeyPublicKey<ECPublicKey> {

    public static final String ALGORITHM = "ECDSA-SK";

    private static final long serialVersionUID = -8758432826838775097L;

    private final String appName;
    private final boolean noTouchRequired;
    private final ECPublicKey delegatePublicKey;

    public SkEcdsaPublicKey(String appName, boolean noTouchRequired, ECPublicKey delegatePublicKey) {
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
    public ECPublicKey getDelegatePublicKey() {
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
}
