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

import java.security.PublicKey;
import java.util.List;

public final class OpenSshPublicKey implements PublicKey {

    private static final long serialVersionUID = -3592634724148744943L;

    private PublicKey serverHostKey;
    private long serial;
    private int type;
    private String id;
    private List<String> principals;
    private long validAfter;
    private long validBefore;
    private List<String> criticalOptions;
    private List<String> extensions;
    private PublicKey caPubKey;

    private OpenSshPublicKey() {
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

    public PublicKey getCaPubKey() {
        return caPubKey;
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
        private PublicKey serverHostKey;
        private long serial;
        private int type;
        private String id;
        private List<String> principals;
        private long validAfter;
        private long validBefore;
        private List<String> criticalOptions;
        private List<String> extensions;
        private PublicKey caPubKey;

        private OpenSshPublicKeyBuilder() {
        }

        public static OpenSshPublicKeyBuilder anOpenSshPublicKey() {
            return new OpenSshPublicKeyBuilder();
        }

        public OpenSshPublicKeyBuilder withServerHostKey(PublicKey serverHostKey) {
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

        public OpenSshPublicKeyBuilder withCaPubKey(PublicKey caPubKey) {
            this.caPubKey = caPubKey;
            return this;
        }

        public OpenSshPublicKey build() {
            OpenSshPublicKey openSshPublicKey = new OpenSshPublicKey();
            openSshPublicKey.criticalOptions = this.criticalOptions;
            openSshPublicKey.type = this.type;
            openSshPublicKey.id = this.id;
            openSshPublicKey.validAfter = this.validAfter;
            openSshPublicKey.serverHostKey = this.serverHostKey;
            openSshPublicKey.principals = this.principals;
            openSshPublicKey.extensions = this.extensions;
            openSshPublicKey.validBefore = this.validBefore;
            openSshPublicKey.caPubKey = this.caPubKey;
            openSshPublicKey.serial = this.serial;
            return openSshPublicKey;
        }
    }
}
