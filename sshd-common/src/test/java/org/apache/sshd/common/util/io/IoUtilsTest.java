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

package org.apache.sshd.common.util.io;

import java.nio.file.LinkOption;

import org.apache.sshd.common.util.NumberUtils;
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
public class IoUtilsTest extends JUnitTestSupport {
    public IoUtilsTest() {
        super();
    }

    @Test
    public void testFollowLinks() {
        assertTrue("Null ?", IoUtils.followLinks((LinkOption[]) null));
        assertTrue("Empty ?", IoUtils.followLinks(IoUtils.EMPTY_LINK_OPTIONS));
        assertFalse("No-follow ?", IoUtils.followLinks(IoUtils.getLinkOptions(false)));
    }

    @Test
    public void testGetEOLBytes() {
        byte[] expected = IoUtils.getEOLBytes();
        assertTrue("Empty bytes", NumberUtils.length(expected) > 0);

        for (int index = 1; index < Byte.SIZE; index++) {
            byte[] actual = IoUtils.getEOLBytes();
            assertNotSame("Same bytes received at iteration " + index, expected, actual);
            assertArrayEquals("Mismatched bytes at iteration " + index, expected, actual);
        }
    }

}
