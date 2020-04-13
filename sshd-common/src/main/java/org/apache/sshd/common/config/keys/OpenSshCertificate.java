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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public final class OpenSshCertificate implements PublicKey, PrivateKey {
    public static final int SSH_CERT_TYPE_USER = 1;
    public static final int SSH_CERT_TYPE_HOST = 2;

    private static final long serialVersionUID = -3592634724148744943L;

    private String keyType;
    private byte[] nonce;
    private PublicKey serverHostKey;
    private long serial;
    private int type;
    private String id;
    private List<String> principals;
    private long validAfter;
    private long validBefore;
    private List<String> criticalOptions;
    private List<String> extensions;
    private String reserved;
    private PublicKey caPubKey;
    private byte[] message;
    private byte[] signature;

    private byte[] rawData;

    private OpenSshCertificate() {
    }

    public static String getRawKeyType(String keyType) {
        return keyType.split("@")[0].substring(0, keyType.indexOf("-cert"));
    }

    public String getRawKeyType() {
        return getRawKeyType(keyType);
    }

    public byte[] getNonce() {
        return nonce;
    }

    public String getKeyType() {
        return keyType;
    }

    public PublicKey getServerHostKey() {
        return serverHostKey;
    }

    public long getSerial() {
        return serial;
    }

    public int getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public List<String> getPrincipals() {
        return principals;
    }

    public long getValidAfter() {
        return validAfter;
    }

    public long getValidBefore() {
        return validBefore;
    }

    public List<String> getCriticalOptions() {
        return criticalOptions;
    }

    public List<String> getExtensions() {
        return extensions;
    }

    public String getReserved() {
        return reserved;
    }

    public PublicKey getCaPubKey() {
        return caPubKey;
    }

    public byte[] getMessage() {
        return message;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setRawData(byte[] rawData) {
        this.rawData = rawData;
    }

    public byte[] getRawData() {
        return rawData;
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    public static final class OpenSshPublicKeyBuilder {
        private String keyType;
        private byte[] nonce;
        private PublicKey serverHostKey;
        private long serial;
        private int type;
        private String id;
        private List<String> principals;
        private long validAfter;
        private long validBefore;
        private List<String> criticalOptions;
        private List<String> extensions;
        private String reserved;
        private PublicKey caPubKey;
        private byte[] message;
        private byte[] signature;

        private OpenSshPublicKeyBuilder() {
        }

        public static OpenSshPublicKeyBuilder anOpenSshCertificate() {
            return new OpenSshPublicKeyBuilder();
        }

        public OpenSshPublicKeyBuilder withKeyType(String keyType) {
            this.keyType = keyType;
            return this;
        }

        public OpenSshPublicKeyBuilder withNonce(byte[] nonce) {
            this.nonce = nonce;
            return this;
        }

        public OpenSshPublicKeyBuilder withServerHostPublicKey(PublicKey serverHostKey) {
            this.serverHostKey = serverHostKey;
            return this;
        }

        public OpenSshPublicKeyBuilder withSerial(long serial) {
            this.serial = serial;
            return this;
        }

        public OpenSshPublicKeyBuilder withType(int type) {
            this.type = type;
            return this;
        }

        public OpenSshPublicKeyBuilder withId(String id) {
            this.id = id;
            return this;
        }

        public OpenSshPublicKeyBuilder withPrincipals(List<String> principals) {
            this.principals = principals;
            return this;
        }

        public OpenSshPublicKeyBuilder withValidAfter(long validAfter) {
            this.validAfter = validAfter;
            return this;
        }

        public OpenSshPublicKeyBuilder withValidBefore(long validBefore) {
            this.validBefore = validBefore;
            return this;
        }

        public OpenSshPublicKeyBuilder withCriticalOptions(List<String> criticalOptions) {
            this.criticalOptions = criticalOptions;
            return this;
        }

        public OpenSshPublicKeyBuilder withExtensions(List<String> extensions) {
            this.extensions = extensions;
            return this;
        }

        public OpenSshPublicKeyBuilder withReserved(String reserved) {
            this.reserved = reserved;
            return this;
        }

        public OpenSshPublicKeyBuilder withCaPubKey(PublicKey caPubKey) {
            this.caPubKey = caPubKey;
            return this;
        }

        public OpenSshPublicKeyBuilder withMessage(byte[] message) {
            this.message = message;
            return this;
        }

        public OpenSshPublicKeyBuilder withSignature(byte[] signature) {
            this.signature = signature;
            return this;
        }

        public OpenSshCertificate build() {
            OpenSshCertificate openSshCertificate = new OpenSshCertificate();
            openSshCertificate.keyType = this.keyType;
            openSshCertificate.nonce = this.nonce;
            openSshCertificate.serverHostKey = this.serverHostKey;
            openSshCertificate.serial = this.serial;
            openSshCertificate.type = this.type;
            openSshCertificate.id = this.id;
            openSshCertificate.principals = this.principals;
            openSshCertificate.validAfter = this.validAfter;
            openSshCertificate.validBefore = this.validBefore;
            openSshCertificate.criticalOptions = this.criticalOptions;
            openSshCertificate.extensions = this.extensions;
            openSshCertificate.reserved = this.reserved;
            openSshCertificate.caPubKey = this.caPubKey;
            openSshCertificate.message = this.message;
            openSshCertificate.signature = this.signature;
            return openSshCertificate;
        }
    }
}
