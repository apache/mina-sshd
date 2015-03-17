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

package org.apache.sshd;

import java.util.List;

import org.apache.sshd.SshBuilder.BaseBuilder;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.BaseTest;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshBuilderTest extends BaseTest {
    public SshBuilderTest() {
        super();
    }

    /**
     * Make sure that {@link BaseBuilder#setUpDefaultCiphers(boolean)} returns
     * the correct result - i.e., according to the {@code ingoreUnsupported}
     * parameter and in the defined preference order
     */
    @Test
    public void testSetUpDefaultCiphers() {
        for (boolean ignoreUnsupported : new boolean[] { true, false }) {
            List<NamedFactory<Cipher>>  ciphers=BaseBuilder.setUpDefaultCiphers(ignoreUnsupported);
            int                         numCiphers=GenericUtils.size(ciphers);
            // make sure returned list size matches expected count
            if (ignoreUnsupported) {
                Assert.assertEquals("Incomplete full ciphers size", BaseBuilder.DEFAULT_CIPHERS_PREFERENCE.size(), numCiphers);
            } else {
                int expectedCount=0;
                for (BuiltinCiphers c : BaseBuilder.DEFAULT_CIPHERS_PREFERENCE) {
                    if (c.isSupported()) {
                        expectedCount++;
                    }
                }
                Assert.assertEquals("Incomplete supported ciphers size", expectedCount, numCiphers);
            }
            
            // make sure order is according to the default preference list
            List<String>    cipherNames=NamedFactory.Utils.getNameList(ciphers);
            int             nameIndex=0;
            for (BuiltinCiphers c : BaseBuilder.DEFAULT_CIPHERS_PREFERENCE) {
                if ((!c.isSupported()) && (!ignoreUnsupported)) {
                    continue;
                }
                
                String  expectedName=c.getName();
                Assert.assertTrue("Out of actual ciphers for expected=" + expectedName, nameIndex < numCiphers);
                
                String  actualName=cipherNames.get(nameIndex);
                Assert.assertEquals("Mismatched cipher at position " + nameIndex + " for ignoreUnsupported=" + ignoreUnsupported, expectedName, actualName);
                nameIndex++;
            }
        }
    }
}
