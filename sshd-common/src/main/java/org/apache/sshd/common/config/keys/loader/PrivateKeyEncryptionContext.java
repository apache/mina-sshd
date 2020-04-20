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
package org.apache.sshd.common.config.keys.loader;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.common.auth.MutablePassword;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PrivateKeyEncryptionContext implements MutablePassword, Cloneable {
    public static final String DEFAULT_CIPHER_MODE = "CBC";

    private static final Map<String, PrivateKeyObfuscator> OBFUSCATORS
            = Stream.of(AESPrivateKeyObfuscator.INSTANCE, DESPrivateKeyObfuscator.INSTANCE)
                    .collect(Collectors.toMap(
                            AbstractPrivateKeyObfuscator::getCipherName, Function.identity(),
                            GenericUtils.throwingMerger(), () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));

    private String cipherName;
    private String cipherType;
    private String cipherMode = DEFAULT_CIPHER_MODE;
    private String password;
    private byte[] initVector;
    private transient PrivateKeyObfuscator obfuscator;

    public PrivateKeyEncryptionContext() {
        super();
    }

    public PrivateKeyEncryptionContext(String algInfo) {
        parseAlgorithmInfo(algInfo);
    }

    public String getCipherName() {
        return cipherName;
    }

    public void setCipherName(String value) {
        cipherName = value;
    }

    public String getCipherType() {
        return cipherType;
    }

    public void setCipherType(String value) {
        cipherType = value;
    }

    public String getCipherMode() {
        return cipherMode;
    }

    public void setCipherMode(String value) {
        cipherMode = value;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public void setPassword(String value) {
        password = value;
    }

    public byte[] getInitVector() {
        return initVector;
    }

    public void setInitVector(byte... values) {
        initVector = values;
    }

    public PrivateKeyObfuscator getPrivateKeyObfuscator() {
        return obfuscator;
    }

    public void setPrivateKeyObfuscator(PrivateKeyObfuscator value) {
        obfuscator = value;
    }

    public PrivateKeyObfuscator resolvePrivateKeyObfuscator() {
        PrivateKeyObfuscator value = getPrivateKeyObfuscator();
        if (value != null) {
            return value;
        }

        return getRegisteredPrivateKeyObfuscator(getCipherName());
    }

    public static PrivateKeyObfuscator registerPrivateKeyObfuscator(PrivateKeyObfuscator o) {
        return registerPrivateKeyObfuscator(Objects.requireNonNull(o, "No instance provided").getCipherName(), o);
    }

    public static PrivateKeyObfuscator registerPrivateKeyObfuscator(String cipherName, PrivateKeyObfuscator o) {
        ValidateUtils.checkNotNullAndNotEmpty(cipherName, "No cipher name");
        Objects.requireNonNull(o, "No instance provided");

        synchronized (OBFUSCATORS) {
            return OBFUSCATORS.put(cipherName, o);
        }
    }

    public static boolean unregisterPrivateKeyObfuscator(PrivateKeyObfuscator o) {
        Objects.requireNonNull(o, "No instance provided");
        String cipherName = o.getCipherName();
        ValidateUtils.checkNotNullAndNotEmpty(cipherName, "No cipher name");

        synchronized (OBFUSCATORS) {
            PrivateKeyObfuscator prev = OBFUSCATORS.get(cipherName);
            if (prev != o) {
                return false;
            }

            OBFUSCATORS.remove(cipherName);
        }

        return true;
    }

    public static PrivateKeyObfuscator unregisterPrivateKeyObfuscator(String cipherName) {
        ValidateUtils.checkNotNullAndNotEmpty(cipherName, "No cipher name");

        synchronized (OBFUSCATORS) {
            return OBFUSCATORS.remove(cipherName);
        }
    }

    public static final PrivateKeyObfuscator getRegisteredPrivateKeyObfuscator(String cipherName) {
        if (GenericUtils.isEmpty(cipherName)) {
            return null;
        }

        synchronized (OBFUSCATORS) {
            return OBFUSCATORS.get(cipherName);
        }
    }

    public static final NavigableSet<String> getRegisteredPrivateKeyObfuscatorCiphers() {
        synchronized (OBFUSCATORS) {
            Collection<String> names = OBFUSCATORS.keySet();
            return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, names);
        }
    }

    public static final List<PrivateKeyObfuscator> getRegisteredPrivateKeyObfuscators() {
        synchronized (OBFUSCATORS) {
            Collection<? extends PrivateKeyObfuscator> l = OBFUSCATORS.values();
            if (GenericUtils.isEmpty(l)) {
                return Collections.emptyList();
            } else {
                return new ArrayList<>(l);
            }
        }
    }

    /**
     * @param  algInfo The algorithm info - format: <I>{@code name-type-mode}</I>
     * @return         The updated context instance
     * @see            #parseAlgorithmInfo(PrivateKeyEncryptionContext, String)
     */
    public PrivateKeyEncryptionContext parseAlgorithmInfo(String algInfo) {
        return parseAlgorithmInfo(this, algInfo);
    }

    @Override
    public PrivateKeyEncryptionContext clone() {
        try {
            PrivateKeyEncryptionContext copy = getClass().cast(super.clone());
            byte[] v = copy.getInitVector();
            if (v != null) {
                v = v.clone();
                copy.setInitVector(v);
            }
            return copy;
        } catch (CloneNotSupportedException e) { // unexpected
            throw new RuntimeException("Failed to clone: " + toString());
        }
    }

    @Override
    public int hashCode() {
        return GenericUtils.hashCode(getCipherName(), Boolean.TRUE)
               + GenericUtils.hashCode(getCipherType(), Boolean.TRUE)
               + GenericUtils.hashCode(getCipherMode(), Boolean.TRUE)
               + Objects.hashCode(getPassword())
               + Arrays.hashCode(getInitVector());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        PrivateKeyEncryptionContext other = (PrivateKeyEncryptionContext) obj;
        return (GenericUtils.safeCompare(getCipherName(), other.getCipherName(), false) == 0)
                && (GenericUtils.safeCompare(getCipherType(), other.getCipherType(), false) == 0)
                && (GenericUtils.safeCompare(getCipherMode(), other.getCipherMode(), false) == 0)
                && (GenericUtils.safeCompare(getPassword(), other.getPassword(), true) == 0)
                && Arrays.equals(getInitVector(), other.getInitVector());
    }

    @Override
    public String toString() {
        return GenericUtils.join(new String[] { getCipherName(), getCipherType(), getCipherMode() }, '-');
    }

    /**
     * @param  <C>     Generic context type
     * @param  context The {@link PrivateKeyEncryptionContext} to update
     * @param  algInfo The algorithm info - format: {@code <I>name</I>-<I>type</I>-<I>mode</I>}
     * @return         The updated context
     */
    public static final <C extends PrivateKeyEncryptionContext> C parseAlgorithmInfo(C context, String algInfo) {
        ValidateUtils.checkNotNullAndNotEmpty(algInfo, "No encryption algorithm data");

        String[] cipherData = GenericUtils.split(algInfo, '-');
        ValidateUtils.checkTrue(cipherData.length == 3, "Bad encryption algorithm data: %s", algInfo);

        context.setCipherName(cipherData[0]);
        context.setCipherType(cipherData[1]);
        context.setCipherMode(cipherData[2]);
        return context;
    }

    public static final PrivateKeyEncryptionContext newPrivateKeyEncryptionContext(PrivateKeyObfuscator o, String password) {
        return initializeObfuscator(new PrivateKeyEncryptionContext(), o, password);
    }

    public static final <
            C extends PrivateKeyEncryptionContext> C initializeObfuscator(C context, PrivateKeyObfuscator o, String password) {
        context.setCipherName(o.getCipherName());
        context.setPrivateKeyObfuscator(o);
        context.setPassword(password);
        return context;
    }
}
