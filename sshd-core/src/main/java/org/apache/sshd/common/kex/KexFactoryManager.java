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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.kex.extension.KexExtensionHandlerManager;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Holds KEX negotiation stage configuration
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KexFactoryManager extends SignatureFactoriesManager, KexExtensionHandlerManager {
    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     *
     * @return a list of named <code>KeyExchange</code> factories, never {@code null}
     */
    List<KeyExchangeFactory> getKeyExchangeFactories();

    void setKeyExchangeFactories(List<KeyExchangeFactory> keyExchangeFactories);

    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     *
     * @return a list of named <code>Cipher</code> factories, never {@code null}
     */
    List<NamedFactory<Cipher>> getCipherFactories();

    default String getCipherFactoriesNameList() {
        return NamedResource.getNames(getCipherFactories());
    }

    default List<String> getCipherFactoriesNames() {
        return NamedResource.getNameList(getCipherFactories());
    }

    void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories);

    default void setCipherFactoriesNameList(String names) {
        setCipherFactoriesNames(GenericUtils.split(names, ','));
    }

    default void setCipherFactoriesNames(String... names) {
        setCipherFactoriesNames(GenericUtils.isEmpty((Object[]) names) ? Collections.emptyList() : Arrays.asList(names));
    }

    default void setCipherFactoriesNames(Collection<String> names) {
        BuiltinCiphers.ParseResult result = BuiltinCiphers.parseCiphersList(names);
        @SuppressWarnings({ "rawtypes", "unchecked" })
        List<NamedFactory<Cipher>> factories = (List) ValidateUtils.checkNotNullAndNotEmpty(result.getParsedFactories(),
                "No supported cipher factories: %s", names);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(GenericUtils.isEmpty(unsupported), "Unsupported cipher factories found: %s", unsupported);
        setCipherFactories(factories);
    }

    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     *
     * @return a list of named <code>Compression</code> factories, never {@code null}
     */
    List<NamedFactory<Compression>> getCompressionFactories();

    default String getCompressionFactoriesNameList() {
        return NamedResource.getNames(getCompressionFactories());
    }

    default List<String> getCompressionFactoriesNames() {
        return NamedResource.getNameList(getCompressionFactories());
    }

    void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories);

    default void setCompressionFactoriesNameList(String names) {
        setCompressionFactoriesNames(GenericUtils.split(names, ','));
    }

    default void setCompressionFactoriesNames(String... names) {
        setCompressionFactoriesNames(GenericUtils.isEmpty((Object[]) names) ? Collections.emptyList() : Arrays.asList(names));
    }

    default void setCompressionFactoriesNames(Collection<String> names) {
        BuiltinCompressions.ParseResult result = BuiltinCompressions.parseCompressionsList(names);
        @SuppressWarnings({ "rawtypes", "unchecked" })
        List<NamedFactory<Compression>> factories = (List) ValidateUtils.checkNotNullAndNotEmpty(result.getParsedFactories(),
                "No supported compression factories: %s", names);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(GenericUtils.isEmpty(unsupported), "Unsupported compression factories found: %s", unsupported);
        setCompressionFactories(factories);
    }

    /**
     * Retrieve the list of named factories for <code>Mac</code>.
     *
     * @return a list of named <code>Mac</code> factories, never {@code null}
     */
    List<NamedFactory<Mac>> getMacFactories();

    default String getMacFactoriesNameList() {
        return NamedResource.getNames(getMacFactories());
    }

    default List<String> getMacFactoriesNames() {
        return NamedResource.getNameList(getMacFactories());
    }

    void setMacFactories(List<NamedFactory<Mac>> macFactories);

    default void setMacFactoriesNameList(String names) {
        setMacFactoriesNames(GenericUtils.split(names, ','));
    }

    default void setMacFactoriesNames(String... names) {
        setMacFactoriesNames(GenericUtils.isEmpty((Object[]) names) ? Collections.emptyList() : Arrays.asList(names));
    }

    default void setMacFactoriesNames(Collection<String> names) {
        BuiltinMacs.ParseResult result = BuiltinMacs.parseMacsList(names);
        @SuppressWarnings({ "rawtypes", "unchecked" })
        List<NamedFactory<Mac>> factories = (List) ValidateUtils.checkNotNullAndNotEmpty(result.getParsedFactories(),
                "No supported MAC factories: %s", names);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(GenericUtils.isEmpty(unsupported), "Unsupported MAC factories found: %s", unsupported);
        setMacFactories(factories);
    }
}
