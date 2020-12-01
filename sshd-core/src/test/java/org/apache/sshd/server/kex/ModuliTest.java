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
package org.apache.sshd.server.kex;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.kex.Moduli.DhGroup;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ModuliTest extends JUnitTestSupport {
    public ModuliTest() {
        super();
    }

    @BeforeClass
    @AfterClass
    public static void clearInternalModuliCache() {
        Moduli.clearInternalModuliCache();
    }

    @Before
    @After
    public void clearCache() {
        clearInternalModuliCache();
    }

    @Test
    public void testLoadInternalModuli() throws IOException {
        URL moduli = getClass().getResource(Moduli.INTERNAL_MODULI_RESPATH);
        assertNotNull("Missing internal moduli resource", moduli);

        List<DhGroup> expected = Moduli.loadInternalModuli(moduli);
        assertTrue("No moduli groups parsed", GenericUtils.isNotEmpty(expected));

        for (int index = 1; index <= Byte.SIZE; index++) {
            List<DhGroup> actual = Moduli.loadInternalModuli(moduli);
            assertSame("Mismatched cached instance at retry #" + index, expected, actual);
        }
    }

    @Test
    public void testKeySizesCoverage() throws IOException {
        URL moduli = getClass().getResource(Moduli.INTERNAL_MODULI_RESPATH);
        List<DhGroup> groups = Moduli.loadInternalModuli(moduli);
        Collection<Integer> actualSizes = new TreeSet<>(Comparator.naturalOrder());
        for (DhGroup g : groups) {
            int size = g.getSize();
            // SSHD-1108 - raised default minimum to 2048...
            assertTrue("Size below min. required " + 1024 + ": " + size, size >= 1024);
            assertTrue("Size above max. allowed " + SecurityUtils.MAX_DHGEX_KEY_SIZE, size <= SecurityUtils.MAX_DHGEX_KEY_SIZE);
            actualSizes.add(size);
        }

        assertListEquals("Mismatched groups size", Arrays.asList(1024, 1536, 2048, 3072, 4096, 6144, 7670, 8192),
                new ArrayList<>(actualSizes));
    }
}
