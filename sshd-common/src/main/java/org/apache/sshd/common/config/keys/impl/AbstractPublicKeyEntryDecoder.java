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

package org.apache.sshd.common.config.keys.impl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Map;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Useful base class implementation for a decoder of an {@code OpenSSH} encoded key data
 *
 * @param  <PUB> Type of {@link PublicKey}
 * @param  <PRV> Type of {@link PrivateKey}
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPublicKeyEntryDecoder<PUB extends PublicKey, PRV extends PrivateKey>
        extends AbstractKeyEntryResolver<PUB, PRV>
        implements PublicKeyEntryDecoder<PUB, PRV> {
    protected AbstractPublicKeyEntryDecoder(Class<PUB> pubType, Class<PRV> prvType, Collection<String> names) {
        super(pubType, prvType, names);
    }

    protected final boolean parseBooleanHeader(Map<String, String> headers, String propertyKey, boolean defaultVal) {
        if (GenericUtils.isEmpty(headers) || !headers.containsKey(propertyKey)) {
            return defaultVal;
        }
        String stringVal = headers.get(propertyKey);
        Boolean boolVal;
        try {
            boolVal = PropertyResolverUtils.parseBoolean(stringVal);
        } catch (IllegalArgumentException e) {
            log.warn("Ignoring non-boolean property value for \"" + propertyKey + "\": " + stringVal);
            boolVal = null;
        }
        if (boolVal == null) {
            return defaultVal;
        }
        return boolVal;
    }
}
