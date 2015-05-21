/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.keyprovider;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.util.AbstractLoggingBean;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.KeyUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractKeyPairProvider extends AbstractLoggingBean implements KeyPairProvider {
    protected AbstractKeyPairProvider() {
        super();
    }

    @Override
    public KeyPair loadKey(String type) {
        ValidateUtils.checkNotNullAndNotEmpty(type, "No key type to load", GenericUtils.EMPTY_OBJECT_ARRAY);

        Iterable<KeyPair> keys = loadKeys();
        for (KeyPair key : keys) {
            if (type.equals(KeyUtils.getKeyType(key))) {
                return key;
            }
        }
        return null;
    }

    @Override
    public List<String> getKeyTypes() {
        List<String> types = new ArrayList<String>();
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
