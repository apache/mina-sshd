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

package org.apache.sshd.common.mac;

import java.lang.reflect.Field;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.util.BaseTest;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BuiltinMacsTest extends BaseTest {
    public BuiltinMacsTest() {
        super();
    }

    @Test
    public void testFromName() {
        for (BuiltinMacs expected : BuiltinMacs.VALUES) {
            String name = expected.getName();
            BuiltinMacs actual = BuiltinMacs.fromFactoryName(name);
            Assert.assertSame(name, expected, actual);
        }
    }

    @Test
    public void testAllConstantsCovered() throws Exception {
        Set<BuiltinMacs> avail=EnumSet.noneOf(BuiltinMacs.class);
        Field[]             fields=BuiltinMacs.Constants.class.getFields();
        for (Field f : fields) {
            String          name=(String) f.get(null);
            BuiltinMacs  value=BuiltinMacs.fromFactoryName(name);
            Assert.assertNotNull("No match found for " + name, value);
            Assert.assertTrue(name + " re-specified", avail.add(value));
        }
        
        Assert.assertEquals("Incomplete coverage", BuiltinMacs.VALUES, avail);
    }
}
