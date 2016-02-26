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

package org.apache.sshd.common.config.keys;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BuiltinIdentitiesTest extends BaseTestSupport {
    public BuiltinIdentitiesTest() {
        super();
    }

    @Test
    public void testFromName() {
        for (BuiltinIdentities expected : BuiltinIdentities.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                assertSame(name, expected, BuiltinIdentities.fromName(name));
                name = shuffleCase(name);
            }
        }
    }

    @Test
    public void testFromAlgorithm() {
        for (BuiltinIdentities expected : BuiltinIdentities.VALUES) {
            String algorithm = expected.getAlgorithm();
            for (int index = 0; index < algorithm.length(); index++) {
                assertSame(algorithm, expected, BuiltinIdentities.fromAlgorithm(algorithm));
                algorithm = shuffleCase(algorithm);
            }
        }
    }

    @Test
    public void testFromKey() throws GeneralSecurityException {
        for (BuiltinIdentities expected : BuiltinIdentities.VALUES) {
            String name = expected.getName();
            if (!expected.isSupported()) {
                System.out.println("Skip unsupported built-in identity: " + name);
                continue;
            }

            KeyPairGenerator gen = SecurityUtils.getKeyPairGenerator(expected.getAlgorithm());
            KeyPair kp = gen.generateKeyPair();
            outputDebugMessage("Checking built-in identity: %s", name);
            assertSame(name + "[pair]", expected, BuiltinIdentities.fromKeyPair(kp));
            assertSame(name + "[public]", expected, BuiltinIdentities.fromKey(kp.getPublic()));
            assertSame(name + "[private]", expected, BuiltinIdentities.fromKey(kp.getPrivate()));
        }
    }

    @Test
    public void testAllConstantsCovered() throws Exception {
        Field[] fields = BuiltinIdentities.Constants.class.getFields();
        for (Field f : fields) {
            int mods = f.getModifiers();
            if (!Modifier.isStatic(mods)) {
                continue;
            }

            if (!Modifier.isFinal(mods)) {
                continue;
            }

            Class<?> type = f.getType();
            if (!String.class.isAssignableFrom(type)) {
                continue;
            }

            String name = f.getName();
            String value = (String) f.get(null);
            BuiltinIdentities id = BuiltinIdentities.fromName(value);
            assertNotNull("No match found for field " + name + "=" + value, id);
        }
    }
}
