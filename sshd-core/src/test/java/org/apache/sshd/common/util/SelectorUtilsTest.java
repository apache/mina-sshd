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
package org.apache.sshd.common.util;

import java.util.Random;

import org.apache.sshd.util.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SelectorUtilsTest extends BaseTestSupport {
    public SelectorUtilsTest() {
        super();
    }

    @Test
    public void testApplySlashifyRules() {
        for (String expected : new String[] {
                null, "", getCurrentTestName(), getClass().getSimpleName() + "/" + getCurrentTestName(),
                "/" + getClass().getSimpleName(), "/" + getClass().getSimpleName() + "/" + getCurrentTestName()
            }) {
            String actual = SelectorUtils.applySlashifyRules(expected, '/');
            assertSame("Mismatched results for '" + expected + "'", expected, actual);
        }
        
        String[] comps = { getClass().getSimpleName(),  getCurrentTestName() };
        Random rnd = new Random(System.nanoTime());
        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
        for (int index = 0; index < Long.SIZE; index++) {
            if (sb.length() > 0) {
                sb.setLength(0);        // start from scratch
            }
            
            boolean prepend = rnd.nextBoolean();
            if (prepend) {
                slashify(sb, rnd);
            }

            sb.append(comps[0]);
            for (int j = 1; j < comps.length; j++) {
                slashify(sb, rnd);
                sb.append(comps[j]);
            }
            
            boolean append = rnd.nextBoolean();
            if (append) {
                slashify(sb, rnd);
            }
            
            String path = sb.toString();
            sb.setLength(0);
            if (prepend) {
                sb.append('/');
            }

            sb.append(comps[0]);
            for (int j = 1; j < comps.length; j++) {
                sb.append('/').append(comps[j]);
            }
            
            if (append) {
                sb.append('/').append('.');
            }
            
            String expected = sb.toString();
            String actual = SelectorUtils.applySlashifyRules(path, '/');
            assertEquals("Mismatched results for path=" + path, expected, actual);
        }
    }
    

    private static int slashify(StringBuilder sb, Random rnd) {
        int slashes = 1 /* at least one slash */ + rnd.nextInt(Byte.SIZE);
        for (int k = 0; k < slashes; k++) {
            sb.append('/');
        }

        return slashes;
    }

}
