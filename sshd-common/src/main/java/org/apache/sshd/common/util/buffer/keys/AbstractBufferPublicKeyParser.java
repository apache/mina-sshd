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

package org.apache.sshd.common.util.buffer.keys;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @param  <PUB> Type of {@link PublicKey} being extracted
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractBufferPublicKeyParser<PUB extends PublicKey> implements BufferPublicKeyParser<PUB> {
    private final Class<PUB> keyClass;
    private final Collection<String> supported;

    protected AbstractBufferPublicKeyParser(Class<PUB> keyClass, String... supported) {
        this(keyClass, GenericUtils.isEmpty(supported) ? Collections.emptyList() : Arrays.asList(supported));
    }

    protected AbstractBufferPublicKeyParser(Class<PUB> keyClass, Collection<String> supported) {
        this.keyClass = Objects.requireNonNull(keyClass, "No key class");
        this.supported
                = ValidateUtils.checkNotNullAndNotEmpty(supported, "No supported types for %s", keyClass.getSimpleName());
    }

    public Collection<String> getSupportedKeyTypes() {
        return supported;
    }

    public final Class<PUB> getKeyClass() {
        return keyClass;
    }

    @Override
    public boolean isKeyTypeSupported(String keyType) {
        Collection<String> keys = getSupportedKeyTypes();
        return (GenericUtils.length(keyType) > 0)
                && (GenericUtils.size(keys) > 0)
                && keys.contains(keyType);
    }

    protected <S extends KeySpec> PUB generatePublicKey(String algorithm, S keySpec) throws GeneralSecurityException {
        KeyFactory keyFactory = getKeyFactory(algorithm);
        PublicKey key = keyFactory.generatePublic(keySpec);
        Class<PUB> kc = getKeyClass();
        if (!kc.isInstance(key)) {
            throw new InvalidKeySpecException(
                    "Mismatched generated key types: expected=" + kc.getSimpleName() + ", actual=" + key);
        }

        return kc.cast(key);
    }

    protected KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(algorithm);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " - supported=" + getSupportedKeyTypes();
    }
}
