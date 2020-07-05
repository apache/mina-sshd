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

package org.apache.sshd.common.file.nonefs;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.spi.FileSystemProvider;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class NoneFileSystemFactoryTest extends JUnitTestSupport {
    public NoneFileSystemFactoryTest() {
        super();
    }

    @Test
    public void testFileSystemCreation() throws IOException {
        FileSystem fs = NoneFileSystemFactory.INSTANCE.createFileSystem(null);
        FileSystemProvider provider = fs.provider();
        assertEquals("Mismatched provider scheme", NoneFileSystemProvider.SCHEME, provider.getScheme());
    }

    @Test
    public void testUserHomeDirectory() throws IOException {
        assertNull(NoneFileSystemFactory.INSTANCE.getUserHomeDir(null));
    }
}
