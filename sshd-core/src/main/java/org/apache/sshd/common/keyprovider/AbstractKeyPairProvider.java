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
package org.apache.sshd.common.keyprovider;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Provides a default implementation for some {@link KeyPairProvider} methods
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractKeyPairProvider extends AbstractLoggingBean implements KeyPairProvider {
    // TODO move this code as default interface methods in Java-8
    protected AbstractKeyPairProvider() {
        super();
    }

    @Override
    public KeyPair loadKey(String type) {
        ValidateUtils.checkNotNullAndNotEmpty(type, "No key type to load");

        Iterable<KeyPair> keys = loadKeys();
        for (KeyPair key : keys) {
            String keyType = KeyUtils.getKeyType(key);
            if (type.equals(keyType)) {
                return key;
            }
        }
        return null;
    }

    @Override
    public List<String> getKeyTypes() {
        List<String> types = new ArrayList<>();
        Iterable<KeyPair> keys = loadKeys();
        for (KeyPair key : keys) {
            String type = KeyUtils.getKeyType(key);
            if (GenericUtils.isEmpty(type) || types.contains(type)) {
                continue;
            }
            types.add(type);
        }

        return types;
    }
}
