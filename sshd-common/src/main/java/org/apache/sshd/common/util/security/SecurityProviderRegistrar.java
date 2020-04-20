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

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SyspropsMapWrapper;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.IgnoringEmptyMap;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SecurityProviderRegistrar extends SecurityProviderChoice, OptionalFeature, PropertyResolver {
    /**
     * Base name for configuration properties related to security providers
     */
    String CONFIG_PROP_BASE = "org.apache.sshd.security.provider";

    /**
     * Property used to configure whether the provider is enabled regardless of whether it is supported.
     *
     * @see #isEnabled()
     */
    String ENABLED_PROPERTY = "enabled";

    /**
     * Property used to configure whether to use the provider's name rather than its {@link Provider} instance
     *
     * @see #isNamedProviderUsed()
     */
    String NAMED_PROVIDER_PROPERTY = "useNamed";

    String ALL_OPTIONS_VALUE = "all";
    String ALL_OPTIONS_WILDCARD = "*";

    String NO_OPTIONS_VALUE = "none";

    /**
     * All the entities that are used in calls to {@link #isSecurityEntitySupported(Class, String)}
     */
    List<Class<?>> SECURITY_ENTITIES = Collections.unmodifiableList(
            Arrays.asList(
                    Cipher.class, KeyFactory.class, MessageDigest.class,
                    KeyPairGenerator.class, KeyAgreement.class, Mac.class,
                    Signature.class, CertificateFactory.class));

    default String getBasePropertyName() {
        return CONFIG_PROP_BASE + "." + getName();
    }

    default String getConfigurationPropertyName(String name) {
        return getBasePropertyName() + "." + name;
    }

    /**
     * @return {@code true} if the provider is enabled regardless of whether it is supported - default={@code true}.
     *         <B>Note:</B> checks if the provider has been <U>programmatically</U> disabled via
     *         {@link SecurityUtils#setAPrioriDisabledProvider(String, boolean)}
     * @see    #ENABLED_PROPERTY
     */
    default boolean isEnabled() {
        if (SecurityUtils.isAPrioriDisabledProvider(getName())) {
            return false;
        }

        String configPropName = getConfigurationPropertyName(ENABLED_PROPERTY);
        return this.getBooleanProperty(configPropName, true);
    }

    @Override
    default PropertyResolver getParentPropertyResolver() {
        return SyspropsMapWrapper.RAW_PROPS_RESOLVER;
    }

    @Override
    default Map<String, Object> getProperties() {
        return IgnoringEmptyMap.getInstance();
    }

    /**
     * @param  transformation The requested {@link Cipher} transformation
     * @return                {@code true} if this security provider supports the transformation
     * @see                   #isSecurityEntitySupported(Class, String)
     */
    default boolean isCipherSupported(String transformation) {
        return isSecurityEntitySupported(Cipher.class, transformation);
    }

    /**
     * @param  algorithm The {@link KeyFactory} algorithm
     * @return           {@code true} if this security provider supports the algorithm
     * @see              #isSecurityEntitySupported(Class, String)
     */
    default boolean isKeyFactorySupported(String algorithm) {
        return isSecurityEntitySupported(KeyFactory.class, algorithm);
    }

    /**
     * @param  algorithm The {@link MessageDigest} algorithm
     * @return           {@code true} if this security provider supports the algorithm
     * @see              #isSecurityEntitySupported(Class, String)
     */
    default boolean isMessageDigestSupported(String algorithm) {
        return isSecurityEntitySupported(MessageDigest.class, algorithm);
    }

    /**
     * @param  algorithm The {@link KeyPairGenerator} algorithm
     * @return           {@code true} if this security provider supports the algorithm
     * @see              #isSecurityEntitySupported(Class, String)
     */
    default boolean isKeyPairGeneratorSupported(String algorithm) {
        return isSecurityEntitySupported(KeyPairGenerator.class, algorithm);
    }

    /**
     * @param  algorithm The {@link KeyAgreement} algorithm
     * @return           {@code true} if this security provider supports the algorithm
     * @see              #isSecurityEntitySupported(Class, String)
     */
    default boolean isKeyAgreementSupported(String algorithm) {
        return isSecurityEntitySupported(KeyAgreement.class, algorithm);
    }

    /**
     * @param  algorithm The {@link Mac} algorithm
     * @return           {@code true} if this security provider supports the algorithm
     * @see              #isSecurityEntitySupported(Class, String)
     */
    default boolean isMacSupported(String algorithm) {
        return isSecurityEntitySupported(Mac.class, algorithm);
    }

    /**
     * @param  algorithm The {@link Signature} algorithm
     * @return           {@code true} if this security provider supports the algorithm
     * @see              #isSecurityEntitySupported(Class, String)
     */
    default boolean isSignatureSupported(String algorithm) {
        return isSecurityEntitySupported(Signature.class, algorithm);
    }

    /**
     * @param  type The {@link CertificateFactory} type
     * @return      {@code true} if this security provider supports the algorithm
     * @see         #isSecurityEntitySupported(Class, String)
     */
    default boolean isCertificateFactorySupported(String type) {
        return isSecurityEntitySupported(CertificateFactory.class, type);
    }

    /**
     * @param  entityType The requested entity type - its simple name serves to build the configuration property name.
     * @return            Configuration value to use if no specific configuration provided - default=empty
     * @see               #isSecurityEntitySupported(Class, String)
     */
    default String getDefaultSecurityEntitySupportValue(Class<?> entityType) {
        return "";
    }

    default boolean isSecurityEntitySupported(Class<?> entityType, String name) {
        String defaultValue = getDefaultSecurityEntitySupportValue(entityType);
        return isSecurityEntitySupported(this, entityType, name, defaultValue);
    }

    /**
     * @return {@code true} if to use the provider's name rather than its {@link Provider} instance -
     *         default={@code true}
     * @see    #NAMED_PROVIDER_PROPERTY
     * @see    #getSecurityProvider()
     * @see    #registerSecurityProvider(SecurityProviderRegistrar)
     */
    @Override
    default boolean isNamedProviderUsed() {
        return PropertyResolverUtils.getBooleanProperty(this,
                getConfigurationPropertyName(NAMED_PROVIDER_PROPERTY),
                SecurityProviderChoice.super.isNamedProviderUsed());
    }

    /**
     * @param  v Value to be examined
     * @return   {@code true} if the value equals (case insensitive) to either {@link #ALL_OPTIONS_VALUE} or
     *           {@link #ALL_OPTIONS_WILDCARD}
     */
    static boolean isAllOptionsValue(String v) {
        return ALL_OPTIONS_VALUE.equalsIgnoreCase(v)
                || ALL_OPTIONS_WILDCARD.equalsIgnoreCase(v);
    }

    /**
     * Checks whether the requested entity type algorithm/name is listed as supported by the registrar's configuration
     *
     * @param  registrar    The {@link SecurityProviderRegistrar}
     * @param  entityType   The requested entity type - its simple name serves to build the configuration property name.
     * @param  name         The requested algorithm/name - <B>Note:</B> if the requested entity is a {@link Cipher} then
     *                      the argument is assumed to be a possible &quot;/&quot; separated transformation and parsed
     *                      as such in order to retrieve the pure cipher name
     * @param  defaultValue Configuration value to use if no specific configuration provided
     * @return              {@code true} registrar is supported and the value is listed (case <U>insensitive</U>) or *
     *                      the property is one of the &quot;all&quot; markers
     * @see                 SecurityProviderRegistrar#isSupported()
     * @see                 #isAllOptionsValue(String)
     */
    static boolean isSecurityEntitySupported(
            SecurityProviderRegistrar registrar, Class<?> entityType, String name, String defaultValue) {
        return Objects.requireNonNull(registrar, "No registrar instance").isSupported()
                && isSecurityEntitySupported(registrar, registrar.getConfigurationPropertyName(entityType.getSimpleName()),
                        entityType, name, defaultValue);
    }

    static boolean isSecurityEntitySupported(
            PropertyResolver resolver, String propName, Class<?> entityType, String name, String defaultValue) {
        if (GenericUtils.isEmpty(name)) {
            return false;
        }

        String propValue = resolver.getString(propName);
        if (GenericUtils.isEmpty(propValue)) {
            propValue = defaultValue;
        }

        if (NO_OPTIONS_VALUE.equalsIgnoreCase(propValue)) {
            return false;
        }

        String[] values = GenericUtils.split(propValue, ',');
        if (GenericUtils.isEmpty(values)) {
            return false;
        }

        if ((values.length == 1) && isAllOptionsValue(values[0])) {
            return true;
        }

        String effectiveName = getEffectiveSecurityEntityName(entityType, name);
        int index = Arrays.binarySearch(values, effectiveName, String.CASE_INSENSITIVE_ORDER);
        return index >= 0;
    }

    /**
     * Determines the &quot;pure&quot; security entity name - e.g., for {@link Cipher}s it strips the trailing
     * transformation specification in order to extract the base cipher name - e.g., &quot;AES/CBC/NoPadding&quot; =&gt;
     * &quot;AES&quot;
     *
     * @param  entityType The security entity type - ignored if {@code null}
     * @param  name       The effective name - ignored if {@code null}/empty
     * @return            The resolved name
     */
    static String getEffectiveSecurityEntityName(Class<?> entityType, String name) {
        if ((entityType == null) || GenericUtils.isEmpty(name) || (!Cipher.class.isAssignableFrom(entityType))) {
            return name;
        }

        int pos = name.indexOf('/');
        return (pos > 0) ? name.substring(0, pos) : name;
    }

    /**
     * Attempts to register the security provider represented by the registrar if not already registered. <B>Note:</B>
     * if {@link SecurityProviderRegistrar#isNamedProviderUsed()} is {@code true} then the generated provider will be
     * added to the system's list of known providers.
     *
     * @param  registrar The {@link SecurityProviderRegistrar}
     * @return           {@code true} if no provider was previously registered
     * @see              Security#getProvider(String)
     * @see              SecurityProviderRegistrar#getSecurityProvider()
     * @see              Security#addProvider(Provider)
     */
    static boolean registerSecurityProvider(SecurityProviderRegistrar registrar) {
        String name = ValidateUtils.checkNotNullAndNotEmpty(
                (registrar == null) ? null : registrar.getName(), "No name for registrar=%s", registrar);
        Provider p = Security.getProvider(name);
        if (p != null) {
            return false;
        }

        p = ValidateUtils.checkNotNull(
                registrar.getSecurityProvider(), "No provider created for registrar of %s", name);
        if (registrar.isNamedProviderUsed()) {
            Security.addProvider(p);
        }

        return true;
    }

    static SecurityProviderRegistrar findSecurityProviderRegistrarBySecurityEntity(
            Predicate<? super SecurityProviderRegistrar> entitySelector,
            Collection<? extends SecurityProviderRegistrar> registrars) {
        return GenericUtils.findFirstMatchingMember(
                r -> r.isEnabled() && r.isSupported() && entitySelector.test(r), registrars);
    }
}
