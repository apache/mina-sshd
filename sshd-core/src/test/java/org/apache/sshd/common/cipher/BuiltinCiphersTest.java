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

package org.apache.sshd.common.cipher;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers.ParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.BaseTest;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BuiltinCiphersTest extends BaseTest {
    public BuiltinCiphersTest() {
        super();
    }

    @Test
    public void testFromEnumName() {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            String  name=expected.name();

            for (int index=0; index < name.length(); index++) {
                BuiltinCiphers  actual=BuiltinCiphers.fromString(name);
                Assert.assertSame(name + " - mismatched enum values", expected, actual);
                name = shuffleCase(name);   // prepare for next time
            }
        }
    }

    @Test
    public void testFromFactoryName() {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            String  name=expected.getName();
            
            for (int index=0; index < name.length(); index++) {
                BuiltinCiphers  actual=BuiltinCiphers.fromFactoryName(name);
                Assert.assertSame(name + " - mismatched enum values", expected, actual);
                name = shuffleCase(name);   // prepare for next time
            }
        }
    }

    @Test
    public void testFromFactory() {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            if (!expected.isSupported()) {
                System.out.append("Skip unsupported cipher: ").println(expected);
                continue;
            }
            
            NamedFactory<Cipher>    factory=expected;
            Assert.assertEquals(expected.name() + " - mismatched factory names", expected.getName(), factory.getName());

            BuiltinCiphers  actual=BuiltinCiphers.fromFactory(factory);
            Assert.assertSame(expected.getName() + " - mismatched enum values", expected, actual);
        }
    }

    @Test
    public void testAllConstantsCovered() throws Exception {
        Set<BuiltinCiphers> avail=EnumSet.noneOf(BuiltinCiphers.class);
        Field[]             fields=BuiltinCiphers.Constants.class.getFields();
        for (Field f : fields) {
            String          name=(String) f.get(null);
            BuiltinCiphers  value=BuiltinCiphers.fromFactoryName(name);
            Assert.assertNotNull("No match found for " + name, value);
            Assert.assertTrue(name + " re-specified", avail.add(value));
        }
        
        Assert.assertEquals("Incomplete coverage", BuiltinCiphers.VALUES, avail);
    }

    @Test
    public void testSupportedCipher() throws Exception {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            if (!expected.isSupported()) {
                System.out.append("Skip unsupported cipher: ").println(expected);
                continue;
            }
            Cipher cipher = expected.create();
            byte[] key = new byte[cipher.getBlockSize()];
            byte[] iv = new byte[cipher.getIVSize()];
            cipher.init(Cipher.Mode.Encrypt, key, iv);
        }
    }

    @Test
    public void testParseCiphersList() {
        List<String>    builtin=NamedResource.Utils.getNameList(BuiltinCiphers.VALUES);
        List<String>    unknown=Arrays.asList(getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName());
        Random          rnd=new Random();
        for (int index=0; index < (builtin.size() + unknown.size()); index++) {
            Collections.shuffle(builtin, rnd);
            Collections.shuffle(unknown, rnd);
            
            List<String>    weavedList=new ArrayList<String>(builtin.size() + unknown.size());
            for (int bIndex=0, uIndex=0; (bIndex < builtin.size()) || (uIndex < unknown.size()); ) {
                boolean useBuiltin=false;
                if (bIndex < builtin.size()) {
                    useBuiltin = (uIndex < unknown.size()) ? rnd.nextBoolean() : true;
                }

                if (useBuiltin) {
                    weavedList.add(builtin.get(bIndex));
                    bIndex++;
                } else if (uIndex < unknown.size()){
                    weavedList.add(unknown.get(uIndex));
                    uIndex++;
                }
            }

            String          fullList=GenericUtils.join(weavedList, ',');
            ParseResult     result=BuiltinCiphers.parseCiphersList(fullList);
            List<String>    parsed=NamedResource.Utils.getNameList(result.getParsedFactories());
            List<String>    missing=result.getUnsupportedFactories();
            
            // makes sure not only that the contents are the same but also the order
            assertListEquals(fullList + "[parsed]", builtin, parsed);
            assertListEquals(fullList + "[unsupported]", unknown, missing);
        }
    }

    @Test
    public void testResolveFactoryOnBuiltinValues() {
        for (NamedFactory<Cipher> expected : BuiltinCiphers.VALUES) {
            String                  name=expected.getName();
            NamedFactory<Cipher>    actual=BuiltinCiphers.resolveFactory(name);
            Assert.assertSame(name, expected, actual);
        }
    }

    @Test
    public void testNotAllowedToRegisterBuiltinFactories() {
        for (CipherFactory expected : BuiltinCiphers.VALUES) {
            try {
                BuiltinCiphers.registerExtension(expected);
                Assert.fail("Unexpected sucess for " + expected.getName());
            } catch(IllegalArgumentException e) {
                // expected - ignored
            }
        }
    }

    @Test(expected=IllegalArgumentException.class)
    public void testNotAllowedToOverrideRegisteredFactories() {
        CipherFactory    expected=Mockito.mock(CipherFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String  name=expected.getName();
        try {
            for (int index=1; index <= Byte.SIZE; index++) {
                BuiltinCiphers.registerExtension(expected);
                Assert.assertEquals("Unexpected success at attempt #" + index, 1, index);
            }
        } finally {
            BuiltinCiphers.unregisterExtension(name);
        }
    }

    @Test
    public void testResolveFactoryOnRegisteredExtension() {
        CipherFactory    expected=Mockito.mock(CipherFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String  name=expected.getName();
        try {
            Assert.assertNull("Extension already registered", BuiltinCiphers.resolveFactory(name));
            BuiltinCiphers.registerExtension(expected);

            NamedFactory<Cipher>    actual=BuiltinCiphers.resolveFactory(name);
            Assert.assertSame("Mismatched resolved instance", expected, actual);
        } finally {
            NamedFactory<Cipher>    actual=BuiltinCiphers.unregisterExtension(name);
            Assert.assertSame("Mismatched unregistered instance", expected, actual);
            Assert.assertNull("Extension not un-registered", BuiltinCiphers.resolveFactory(name));
        }
    }

    @Test
    public void testFac2NamedTransformer() {
        Assert.assertNull("Invalid null transformation", CipherFactory.FAC2NAMED.transform(null));
        for (CipherFactory expected : BuiltinCiphers.VALUES) {
            NamedFactory<Cipher>   actual=CipherFactory.FAC2NAMED.transform(expected);
            Assert.assertSame("Mismatched transformed instance for " + expected.getName(), expected, actual);
        }
        
        CipherFactory   mock=Mockito.mock(CipherFactory.class);
        Assert.assertSame("Mismatched transformed mocked instance", mock, CipherFactory.FAC2NAMED.transform(mock));
    }
}
