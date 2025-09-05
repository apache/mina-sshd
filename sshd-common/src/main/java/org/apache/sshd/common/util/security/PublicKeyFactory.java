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
package org.apache.sshd.common.util.security;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Something that can compute a {@link PublicKey} from a given {@link PrivateKey}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PublicKeyFactory {

    /**
     * Given a {@link PrivateKey} computes the corresponding {@link PublicKey}.
     *
     * @param  key {@link PrivateKey} to get the {@link PublicKey} for
     * @return     the {@link PublicKey}, or {@code null} if no public key could be computed
     */
    PublicKey getPublicKey(PrivateKey key);
}
