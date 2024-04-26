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

package org.apache.sshd.sftp.common;

import org.apache.sshd.sftp.client.SftpClient.Attributes;
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
public class SftpHelperTest extends JUnitTestSupport {

    public SftpHelperTest() {
        super();
    }

    @Test
    public void testPermissionsToFile() {
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_SOCKET, SftpHelper.permissionsToFileType(SftpConstants.S_IFSOCK));
    }

    @Test
    public void testCompleteAttributesNoLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, null);
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-rw-rw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesLongNameDir() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1FF);
        attrs = SftpHelper.complete(attrs, "drwxrwxrwx   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY, attrs.getType());
        assertEquals(0x1FF | SftpConstants.S_IFDIR, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesLongNameT() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1FD);
        attrs = SftpHelper.complete(attrs, "drwxrwxrwT   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY, attrs.getType());
        assertEquals(0x1FD | SftpConstants.S_IFDIR, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesLongNameS() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1BD);
        attrs = SftpHelper.complete(attrs, "-rw-rwSrw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1BD | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesLongNameLink() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1FF);
        attrs = SftpHelper.complete(attrs, "lrwxrwxrwx   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_SYMLINK, attrs.getType());
        assertEquals(0x1FF | SftpConstants.S_IFLNK, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesSolarWindsLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-rw-rw   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesWinLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-******   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesOsxLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-rw-rw-@   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesUnknownLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-demo.csv 1944 2024-04-24'T'14:58:01");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesBrokenLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "rw-rw-rw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }

    @Test
    public void testCompleteAttributesBrokenLongName2() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "Qrw-rw-rw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }
}
