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

package org.apache.sshd.common.config;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.function.Function;

import org.apache.sshd.common.BuiltinFactory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Reads and interprets some useful configurations from an OpenSSH configuration file.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">ssh_config(5)</a>
 */
public final class SshConfigFileReader {
    private SshConfigFileReader() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @param  props The {@link PropertyResolver} - ignored if {@code null}/empty
     * @return       A {@code ParseResult} of all the {@link NamedFactory}-ies whose name appears in the string and
     *               represent a built-in cipher. Any unknown name is <U>ignored</U>. The order of the returned result
     *               is the same as the original order - bar the unknown ciphers. <B>Note:</B> it is up to caller to
     *               ensure that the lists do not contain duplicates
     * @see          ConfigFileReaderSupport#CIPHERS_CONFIG_PROP CIPHERS_CONFIG_PROP
     * @see          BuiltinCiphers#parseCiphersList(String)
     */
    public static BuiltinCiphers.ParseResult getCiphers(PropertyResolver props) {
        return BuiltinCiphers.parseCiphersList(
                (props == null) ? null : props.getString(ConfigFileReaderSupport.CIPHERS_CONFIG_PROP));
    }

    /**
     * @param  props The {@link PropertyResolver} - ignored if {@code null}/empty
     * @return       A {@code ParseResult} of all the {@link NamedFactory}-ies whose name appears in the string and
     *               represent a built-in MAC. Any unknown name is <U>ignored</U>. The order of the returned result is
     *               the same as the original order - bar the unknown MACs. <B>Note:</B> it is up to caller to ensure
     *               that the list does not contain duplicates
     * @see          ConfigFileReaderSupport#MACS_CONFIG_PROP MACS_CONFIG_PROP
     * @see          BuiltinMacs#parseMacsList(String)
     */
    public static BuiltinMacs.ParseResult getMacs(PropertyResolver props) {
        return BuiltinMacs.parseMacsList(
                (props == null) ? null : props.getString(ConfigFileReaderSupport.MACS_CONFIG_PROP));
    }

    /**
     * @param  props The {@link PropertyResolver} - ignored if {@code null}/empty
     * @return       A {@code ParseResult} of all the {@link NamedFactory} whose name appears in the string and
     *               represent a built-in signature. Any unknown name is <U>ignored</U>. The order of the returned
     *               result is the same as the original order - bar the unknown signatures. <B>Note:</B> it is up to
     *               caller to ensure that the list does not contain duplicates
     * @see          ConfigFileReaderSupport#HOST_KEY_ALGORITHMS_CONFIG_PROP HOST_KEY_ALGORITHMS_CONFIG_PROP
     * @see          BuiltinSignatures#parseSignatureList(String)
     */
    public static BuiltinSignatures.ParseResult getSignatures(PropertyResolver props) {
        return BuiltinSignatures.parseSignatureList(
                (props == null) ? null : props.getString(ConfigFileReaderSupport.HOST_KEY_ALGORITHMS_CONFIG_PROP));
    }

    /**
     * @param  props The {@link PropertyResolver} - ignored if {@code null}/empty
     * @return       A {@code ParseResult} of all the {@link DHFactory}-ies whose name appears in the string and
     *               represent a built-in value. Any unknown name is <U>ignored</U>. The order of the returned result is
     *               the same as the original order - bar the unknown ones. <B>Note:</B> it is up to caller to ensure
     *               that the list does not contain duplicates
     * @see          ConfigFileReaderSupport#KEX_ALGORITHMS_CONFIG_PROP KEX_ALGORITHMS_CONFIG_PROP
     * @see          BuiltinDHFactories#parseDHFactoriesList(String)
     */
    public static BuiltinDHFactories.ParseResult getKexFactories(PropertyResolver props) {
        return BuiltinDHFactories.parseDHFactoriesList(
                (props == null) ? null : props.getString(ConfigFileReaderSupport.KEX_ALGORITHMS_CONFIG_PROP));
    }

    /**
     * @param  props The {@link PropertyResolver} - ignored if {@code null}/empty
     * @return       The matching {@link NamedFactory} for the configured value. {@code null} if no configuration or
     *               unknown name specified
     * @see          ConfigFileReaderSupport#COMPRESSION_PROP COMPRESSION_PROP
     */
    public static CompressionFactory getCompression(PropertyResolver props) {
        return CompressionConfigValue.fromName(
                (props == null) ? null : props.getString(ConfigFileReaderSupport.COMPRESSION_PROP));
    }

    /**
     * <P>
     * Configures an {@link AbstractFactoryManager} with the values read from some configuration. Currently it
     * configures:
     * </P>
     * <UL>
     * <LI>The {@link Cipher}s - via the {@link ConfigFileReaderSupport#CIPHERS_CONFIG_PROP}</LI>
     * <LI>The {@link Mac}s - via the {@link ConfigFileReaderSupport#MACS_CONFIG_PROP}</LI>
     * <LI>The {@link Signature}s - via the {@link ConfigFileReaderSupport#HOST_KEY_ALGORITHMS_CONFIG_PROP}</LI>
     * <LI>The {@link Compression} - via the {@link ConfigFileReaderSupport#COMPRESSION_PROP}</LI>
     * </UL>
     *
     * @param  <M>               The generic factory manager
     * @param  manager           The {@link AbstractFactoryManager} to configure
     * @param  props             The {@link PropertyResolver} to use for configuration - <B>Note:</B> if any known
     *                           configuration value has a default and does not appear in the properties, the default is
     *                           used
     * @param  lenient           If {@code true} then any unknown configuration values are ignored. Otherwise an
     *                           {@link IllegalArgumentException} is thrown
     * @param  ignoreUnsupported filter out unsupported configuration values (e.g., ciphers, key exchanges, etc..).
     *                           <B>Note:</B> if after filtering out all the unknown or unsupported values there is an
     *                           empty configuration exception is thrown
     * @return                   The configured manager
     */
    public static <M extends AbstractFactoryManager> M configure(
            M manager, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        configureCiphers(manager, props, lenient, ignoreUnsupported);
        configureSignatures(manager, props, lenient, ignoreUnsupported);
        configureMacs(manager, props, lenient, ignoreUnsupported);
        configureCompression(manager, props, lenient, ignoreUnsupported);

        return manager;
    }

    public static <M extends AbstractFactoryManager> M configureCiphers(
            M manager, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(props, "No properties to configure");
        return configureCiphers(manager,
                props.getString(ConfigFileReaderSupport.CIPHERS_CONFIG_PROP),
                lenient, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureCiphers(
            M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(manager, "No manager to configure");
        if (GenericUtils.isEmpty(value)) {
            return manager;
        }

        BuiltinCiphers.ParseResult result = BuiltinCiphers.parseCiphersList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported),
                "Unsupported cipher(s) (%s) in %s", unsupported, value);

        List<NamedFactory<Cipher>> factories
                = BuiltinFactory.setUpFactories(ignoreUnsupported, result.getParsedFactories());
        manager.setCipherFactories(
                ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/unsupported ciphers(s): %s", value));
        return manager;
    }

    public static <M extends AbstractFactoryManager> M configureSignatures(
            M manager, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(props, "No properties to configure");
        return configureSignatures(manager,
                props.getString(ConfigFileReaderSupport.HOST_KEY_ALGORITHMS_CONFIG_PROP),
                lenient, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureSignatures(
            M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(manager, "No manager to configure");
        if (GenericUtils.isEmpty(value)) {
            return manager;
        }

        BuiltinSignatures.ParseResult result = BuiltinSignatures.parseSignatureList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported),
                "Unsupported signatures (%s) in %s", unsupported, value);

        List<NamedFactory<Signature>> factories
                = BuiltinFactory.setUpFactories(ignoreUnsupported, result.getParsedFactories());
        manager.setSignatureFactories(
                ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/supported signatures: %s", value));
        return manager;
    }

    public static <M extends AbstractFactoryManager> M configureMacs(
            M manager, PropertyResolver resolver, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(resolver, "No properties to configure");
        return configureMacs(manager,
                resolver.getString(ConfigFileReaderSupport.MACS_CONFIG_PROP),
                lenient, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureMacs(
            M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(manager, "No manager to configure");
        if (GenericUtils.isEmpty(value)) {
            return manager;
        }

        BuiltinMacs.ParseResult result = BuiltinMacs.parseMacsList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported),
                "Unsupported MAC(s) (%s) in %s", unsupported, value);

        List<NamedFactory<Mac>> factories = BuiltinFactory.setUpFactories(ignoreUnsupported, result.getParsedFactories());
        manager.setMacFactories(
                ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/supported MAC(s): %s", value));
        return manager;
    }

    /**
     * @param  <M>               The generic factory manager
     * @param  manager           The {@link AbstractFactoryManager} to set up (may not be {@code null})
     * @param  props             The (non-{@code null}) {@link PropertyResolver} containing the configuration
     * @param  lenient           If {@code true} then any unknown/unsupported configuration values are ignored.
     *                           Otherwise an {@link IllegalArgumentException} is thrown
     * @param  xformer           A {@link Function} to convert the configured {@link DHFactory}-ies to
     *                           {@link NamedFactory}-ies of {@link KeyExchange}
     * @param  ignoreUnsupported Filter out any un-supported configurations - <B>Note:</B> if after ignoring the unknown
     *                           and un-supported values the result is an empty list of factories and exception is
     *                           thrown
     * @return                   The configured manager
     * @see                      ConfigFileReaderSupport#KEX_ALGORITHMS_CONFIG_PROP KEX_ALGORITHMS_CONFIG_PROP
     */
    public static <M extends AbstractFactoryManager> M configureKeyExchanges(
            M manager, PropertyResolver props, boolean lenient,
            Function<? super DHFactory, ? extends KeyExchangeFactory> xformer, boolean ignoreUnsupported) {
        Objects.requireNonNull(props, "No properties to configure");
        return configureKeyExchanges(manager,
                props.getString(ConfigFileReaderSupport.KEX_ALGORITHMS_CONFIG_PROP),
                lenient, xformer, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureKeyExchanges(
            M manager, String value, boolean lenient,
            Function<? super DHFactory, ? extends KeyExchangeFactory> xformer, boolean ignoreUnsupported) {
        Objects.requireNonNull(manager, "No manager to configure");
        Objects.requireNonNull(xformer, "No DHFactory transformer");
        if (GenericUtils.isEmpty(value)) {
            return manager;
        }

        BuiltinDHFactories.ParseResult result = BuiltinDHFactories.parseDHFactoriesList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported),
                "Unsupported KEX(s) (%s) in %s", unsupported, value);

        List<KeyExchangeFactory> factories
                = NamedFactory.setUpTransformedFactories(ignoreUnsupported, result.getParsedFactories(), xformer);
        manager.setKeyExchangeFactories(
                ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/supported KEXS(s): %s", value));
        return manager;
    }

    /**
     * Configure the factory manager using one of the known {@link CompressionConfigValue}s.
     *
     * @param  <M>               The generic factory manager
     * @param  manager           The {@link AbstractFactoryManager} to configure
     * @param  props             The configuration {@link Properties}
     * @param  lenient           If {@code true} and an unknown value is provided then it is ignored
     * @param  ignoreUnsupported If {@code false} then check if the compression is currently supported before setting it
     * @return                   The configured manager - <B>Note:</B> if the result of filtering due to lenient mode or
     *                           ignored unsupported value is empty then no factories are set
     */
    public static <M extends AbstractFactoryManager> M configureCompression(
            M manager, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(manager, "No manager to configure");
        Objects.requireNonNull(props, "No properties to configure");

        String value = props.getString(ConfigFileReaderSupport.COMPRESSION_PROP);
        if (GenericUtils.isEmpty(value)) {
            return manager;
        }

        CompressionFactory factory = CompressionConfigValue.fromName(value);
        ValidateUtils.checkTrue(lenient || (factory != null), "Unsupported compression value: %s", value);
        if ((factory != null) && factory.isSupported()) {
            manager.setCompressionFactories(Collections.singletonList(factory));
        }

        return manager;
    }

    // accepts BOTH CompressionConfigValue(s) and/or BuiltinCompressions - including extensions
    public static <M extends AbstractFactoryManager> M configureCompression(
            M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        Objects.requireNonNull(manager, "No manager to configure");
        if (GenericUtils.isEmpty(value)) {
            return manager;
        }

        CompressionFactory factory = CompressionConfigValue.fromName(value);
        if (factory != null) {
            // SSH can work without compression
            if (ignoreUnsupported || factory.isSupported()) {
                manager.setCompressionFactories(Collections.singletonList(factory));
            }
        } else {
            BuiltinCompressions.ParseResult result = BuiltinCompressions.parseCompressionsList(value);
            Collection<String> unsupported = result.getUnsupportedFactories();
            ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported), "Unsupported compressions(s) (%s) in %s",
                    unsupported, value);

            List<NamedFactory<Compression>> factories
                    = BuiltinFactory.setUpFactories(ignoreUnsupported, result.getParsedFactories());
            // SSH can work without compression
            if (GenericUtils.size(factories) > 0) {
                manager.setCompressionFactories(factories);
            }
        }

        return manager;
    }
}
