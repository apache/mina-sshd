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
package org.apache.sshd.client.auth.pubkey;

import java.io.IOException;
import java.util.List;

import org.apache.sshd.client.auth.AbstractUserAuthFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKeyFactory extends AbstractUserAuthFactory implements SignatureFactoriesManager {
    public static final String NAME = PUBLIC_KEY;
    public static final UserAuthPublicKeyFactory INSTANCE = new UserAuthPublicKeyFactory() {
        @Override
        public List<NamedFactory<Signature>> getSignatureFactories() {
            return null;
        }

        @Override
        public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
            if (!GenericUtils.isEmpty(factories)) {
                throw new UnsupportedOperationException("Not allowed to change default instance signature factories");
            }
        }
    };

    private List<NamedFactory<Signature>> factories;

    public UserAuthPublicKeyFactory() {
        this(null);
    }

    public UserAuthPublicKeyFactory(List<NamedFactory<Signature>> factories) {
        super(NAME);
        this.factories = factories; // OK if null/empty
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return factories;
    }

    @Override
    public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
        this.factories = factories;
    }

    @Override
    public UserAuthPublicKey createUserAuth(ClientSession session) throws IOException {
        return new UserAuthPublicKey(getSignatureFactories());
    }
}
