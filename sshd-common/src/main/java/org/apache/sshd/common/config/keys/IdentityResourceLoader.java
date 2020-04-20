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

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @param  <PUB> Type of {@link PublicKey}
 * @param  <PRV> Type of {@link PrivateKey}
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface IdentityResourceLoader<PUB extends PublicKey, PRV extends PrivateKey> extends KeyTypeNamesSupport {
    /**
     * A reasonable max. number of octets used for a {@link BigInteger} in the context of keys based on such numbers
     */
    int MAX_BIGINT_OCTETS_COUNT = Short.MAX_VALUE;

    /**
     * @return The {@link Class} of the {@link PublicKey} that is the result of decoding
     */
    Class<PUB> getPublicKeyType();

    /**
     * @return The {@link Class} of the {@link PrivateKey} that matches the public one
     */
    Class<PRV> getPrivateKeyType();
}
