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
package org.apache.sshd.common.config.keys;

import java.util.Arrays;
import java.util.Objects;

/**
 * A representation of an unsupported SSH public key -- just a key type and the raw key data.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UnsupportedSshPublicKey implements SshPublicKey {

    private static final long serialVersionUID = -4870624671501562706L;

    private final String keyType;

    private final byte[] keyData;

    public UnsupportedSshPublicKey(String keyType, byte[] keyData) {
        this.keyType = keyType;
        this.keyData = keyData.clone();
    }

    @Override
    public String getAlgorithm() {
        // Won't match any JCE algorithm.
        return getKeyType();
    }

    @Override
    public String getFormat() {
        // We cannot produce an encoding for an unsupported key.
        return null;
    }

    @Override
    public byte[] getEncoded() {
        // We cannot produce an encoding for an unsupported key.
        return null;
    }

    @Override
    public String getKeyType() {
        return keyType;
    }

    /**
     * Retrieves the raw key bytes (serialized form).
     *
     * @return the key bytes
     */
    public byte[] getKeyData() {
        return keyData.clone();
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyData) * 31 + Objects.hash(keyType);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UnsupportedSshPublicKey)) {
            return false;
        }
        UnsupportedSshPublicKey other = (UnsupportedSshPublicKey) obj;
        return Arrays.equals(keyData, other.keyData) && Objects.equals(keyType, other.keyType);
    }

}
