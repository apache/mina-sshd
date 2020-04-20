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
package org.apache.sshd.common.util.io.der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class DERWriterTest extends JUnitTestSupport {
    public DERWriterTest() {
        super();
    }

    @Test
    public void testWriteStripLeadingZeroes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            try (DERWriter w = new DERWriter(baos)) {
                w.writeBigInteger(BigInteger.valueOf(-1));
                w.writeBigInteger(BigInteger.valueOf(129));
                w.writeBigInteger(new byte[] { 0, 0 }, 0, 2);
                w.writeBigInteger(new byte[] { 0, 1 }, 0, 2);
            }
        } finally {
            baos.close();
        }

        try (DERParser parser = new DERParser(baos.toByteArray())) {
            assertEquals(BigInteger.valueOf(255), parser.readBigInteger());
            assertEquals(BigInteger.valueOf(129), parser.readBigInteger());
            assertEquals(BigInteger.valueOf(0), parser.readBigInteger());
            assertEquals(BigInteger.valueOf(1), parser.readBigInteger());
        }
    }

}
