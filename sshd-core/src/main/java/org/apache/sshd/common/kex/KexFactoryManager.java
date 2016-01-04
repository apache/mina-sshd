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

package org.apache.sshd.common.kex;

import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.keyprovider.KeyPairProviderHolder;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.SignatureFactoriesManager;

/**
 * Holds KEX negotiation stage configuration
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KexFactoryManager extends KeyPairProviderHolder, SignatureFactoriesManager {
    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     *
     * @return a list of named <code>KeyExchange</code> factories, never {@code null}
     */
    List<NamedFactory<KeyExchange>> getKeyExchangeFactories();
    void setKeyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories);

    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     *
     * @return a list of named <code>Cipher</code> factories, never {@code null}
     */
    List<NamedFactory<Cipher>> getCipherFactories();
    void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories);

    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     *
     * @return a list of named <code>Compression</code> factories, never {@code null}
     */
    List<NamedFactory<Compression>> getCompressionFactories();
    void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories);

    /**
     * Retrieve the list of named factories for <code>Mac</code>.
     *
     * @return a list of named <code>Mac</code> factories, never {@code null}
     */
    List<NamedFactory<Mac>> getMacFactories();
    void setMacFactories(List<NamedFactory<Mac>> macFactories);
}
