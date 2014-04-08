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
package org.apache.sshd.common.file.nativefs;

import org.apache.sshd.util.BaseTest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class NativeSshFileTest extends BaseTest {

    @Test
    public void testResolve() {
        assertEquals("Z:/git/mina-sshd/sshd-core/target/scp/remote/out.txt",
                NativeSshFile.getPhysicalName("Z:\\git/", "Z:\\git\\mina-sshd\\sshd-core", "\\mina-sshd\\sshd-core\\target\\scp\\remote\\out.txt", false));
        assertEquals("Z:/git/mina-sshd/sshd-core/target/scp/remote/out.txt",
                NativeSshFile.getPhysicalName("Z:/", "Z:\\git\\mina-sshd\\sshd-core", "\\git\\mina-sshd\\sshd-core\\target\\scp\\remote\\out.txt", false));
        assertEquals("Z:/git/mina-sshd/sshd-core/target/scp/remote/out.txt",
                NativeSshFile.getPhysicalName("Z:/", "Z:\\git\\mina-sshd\\sshd-core", "/git/mina-sshd/sshd-core/target/scp/remote/out.txt", false));

        assertEquals("/bar", NativeSshFile.getPhysicalName("/", "/foo", "/bar", false));
        assertEquals("/bar", NativeSshFile.getPhysicalName("/", "/", "/bar", false));
        assertEquals("/bar", NativeSshFile.getPhysicalName("/", "/", "bar", false));
        assertEquals("/foo/bar", NativeSshFile.getPhysicalName("/", "/foo", "bar", false));
        assertEquals("/foo/bar", NativeSshFile.getPhysicalName("/", "/foo/xyz", "../bar", false));
        assertEquals("/foo/xyz/bar", NativeSshFile.getPhysicalName("/", "/foo/xyz", "./bar", false));

        assertEquals("/foo/bar", NativeSshFile.getPhysicalName("/foo", "/", "bar", false));
        assertEquals("/foo/bar", NativeSshFile.getPhysicalName("/foo", "/xyz", "../bar", false));
        assertEquals("/foo/bar", NativeSshFile.getPhysicalName("/foo", "/xyz", "../../bar", false));
        assertEquals("/foo/xyz/bar", NativeSshFile.getPhysicalName("/foo", "/xyz", "./bar", false));
    }

}
