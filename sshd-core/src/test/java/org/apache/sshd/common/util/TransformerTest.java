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

package org.apache.sshd.common.util;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TransformerTest extends BaseTestSupport {
    public TransformerTest() {
        super();
    }

    @Test
    public void testToString() {
        assertNull("Invalid null result", Transformer.TOSTRING.transform(null));
        for (Object o : new Object[] {"", getClass(), new Date()}) {
            String expected = o.toString();
            String actual = Transformer.TOSTRING.transform(o);
            assertEquals("Mismatched result for type=" + o.getClass().getSimpleName(), expected, actual);
        }
    }

    @Test
    public void testExtractEnumName() {
        assertNull("Invalid null result", Transformer.ENUM_NAME_EXTRACTOR.transform(null));

        for (TimeUnit u : TimeUnit.values()) {
            String expected = u.name();
            String actual = Transformer.ENUM_NAME_EXTRACTOR.transform(u);
            assertEquals("Mismatched name", expected, actual);
        }
    }

    @Test
    public void testSingletonIdentityInstance() {
        Transformer<Date, Date> dateTransformer = Transformer.Utils.identity();
        Transformer<String, String> stringTransformer = Transformer.Utils.identity();
        assertSame("Mismatched identity instance", dateTransformer, stringTransformer);
    }

    @Test
    public void testIdentity() {
        Transformer<Object, Object> identity = Transformer.Utils.identity();
        for (Object expected : new Object[]{null, getClass(), getCurrentTestName()}) {
            Object actual = identity.transform(expected);
            assertSame("Mismatched identity result", expected, actual);
        }
    }
}
