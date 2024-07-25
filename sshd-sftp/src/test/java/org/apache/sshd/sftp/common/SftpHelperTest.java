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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SftpHelperTest extends JUnitTestSupport {

    public SftpHelperTest() {
        super();
    }

    @Test
    void permissionsToFile() {
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_SOCKET, SftpHelper.permissionsToFileType(SftpConstants.S_IFSOCK));
    }

    @Test
    void completeAttributesNoLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, null);
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }

    @Test
    void completeAttributesLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-rw-rw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    void completeAttributesLongNameDir() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1FF);
        attrs = SftpHelper.complete(attrs, "drwxrwxrwx   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY, attrs.getType());
        assertEquals(0x1FF | SftpConstants.S_IFDIR, attrs.getPermissions());
    }

    @Test
    void completeAttributesLongNameT() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1FD);
        attrs = SftpHelper.complete(attrs, "drwxrwxrwT   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY, attrs.getType());
        assertEquals(0x1FD | SftpConstants.S_IFDIR, attrs.getPermissions());
    }

    @Test
    void completeAttributesLongNameS() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1BD);
        attrs = SftpHelper.complete(attrs, "-rw-rwSrw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1BD | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    void completeAttributesLongNameLink() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1FF);
        attrs = SftpHelper.complete(attrs, "lrwxrwxrwx   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_SYMLINK, attrs.getType());
        assertEquals(0x1FF | SftpConstants.S_IFLNK, attrs.getPermissions());
    }

    @Test
    void completeAttributesSolarWindsLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-rw-rw   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    void completeAttributesWinLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-******   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    void completeAttributesOsxLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-rw-rw-rw-@   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
        assertEquals(0x1B6 | SftpConstants.S_IFREG, attrs.getPermissions());
    }

    @Test
    void completeAttributesUnknownLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "-demo.csv 1944 2024-04-24'T'14:58:01");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }

    @Test
    void completeAttributesBrokenLongName() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "rw-rw-rw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }

    @Test
    void completeAttributesBrokenLongName2() {
        Attributes attrs = new Attributes();
        attrs.setType(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN);
        attrs.setPermissions(0x1B6);
        attrs = SftpHelper.complete(attrs, "Qrw-rw-rw-   1     root     root     1944 Apr 24 14:58 demo.csv");
        assertEquals(SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN, attrs.getType());
        assertEquals(0x1B6, attrs.getPermissions());
    }
}
