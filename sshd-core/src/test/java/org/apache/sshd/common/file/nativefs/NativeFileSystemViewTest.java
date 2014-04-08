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

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class NativeFileSystemViewTest {

    @Test
    public void testResolveWithVirtualRoots() throws Exception {

        Map<String, String> roots = new HashMap<String, String>();
        roots.put("A:", "/fs/rootA");
        roots.put("Z:", "/fs/rootZ");
        String current = "Z:/git";
        NativeFileSystemView view = new NativeFileSystemView("user", roots, current, '/', false);

        assertEquals("Z:/git/foo/bar", view.getFile("foo/bar").getAbsolutePath());
        assertEquals("Z:/foo/bar", view.getFile("../foo/bar").getAbsolutePath());
        assertEquals("A:/temp", view.getFile("A:/./a/../temp").getAbsolutePath());
        assertEquals("A:/temp", view.getFile("A:/../../temp").getAbsolutePath());

        FileSystemView normView = view.getNormalizedView();

        assertEquals("/Z/git/foo/bar", normView.getFile("foo/bar").getAbsolutePath());
        assertEquals("/Z/foo/bar", normView.getFile("../foo/bar").getAbsolutePath());
        assertEquals("/A/temp", normView.getFile("/A/./a/../temp").getAbsolutePath());
        assertEquals("/Z/temp", normView.getFile("/A/../Z/temp").getAbsolutePath());
    }

    @Test
    public void testResolveWithVirtualRootsWithBackslash() throws Exception {

        Map<String, String> roots = new HashMap<String, String>();
        roots.put("A:", "/fs/rootA");
        roots.put("Z:", "/fs/rootZ");
        String current = "Z:/git";
        NativeFileSystemView view = new NativeFileSystemView("user", roots, current, '\\', false);

        assertEquals("Z:\\git\\foo\\bar", view.getFile("/Z:/git/foo/bar").getAbsolutePath());
        assertEquals("Z:\\git\\foo\\bar", view.getFile("foo/bar").getAbsolutePath());
        assertEquals("Z:\\git\\foo", view.getFile("foo/bar").getParentFile().getAbsolutePath());
        assertEquals("Z:\\git", view.getFile("foo/bar").getParentFile().getParentFile().getAbsolutePath());
        assertEquals("Z:\\", view.getFile("foo/bar").getParentFile().getParentFile().getParentFile().getAbsolutePath());
        assertFalse(view.getFile("foo/bar").getParentFile().getParentFile().getParentFile().isRemovable());
        assertEquals("Z:\\foo\\bar", view.getFile("../foo/bar").getAbsolutePath());
        assertEquals("A:\\temp", view.getFile("A:/./a/../temp").getAbsolutePath());
        assertEquals("A:\\temp", view.getFile("A:/../../temp").getAbsolutePath());

        FileSystemView normView = view.getNormalizedView();

        assertEquals("/Z/git/foo/bar", normView.getFile("foo/bar").getAbsolutePath());
        assertEquals("/Z/git/foo", normView.getFile("foo/bar").getParentFile().getAbsolutePath());
        assertEquals("/Z/foo/bar", normView.getFile("../foo/bar").getAbsolutePath());
        assertEquals("/A/temp", normView.getFile("/A/./a/../temp").getAbsolutePath());
        assertEquals("/Z/temp", normView.getFile("/A/../Z/temp").getAbsolutePath());
    }

    @Test
    public void testResolveWithPhysicalRoots() throws Exception {

        Map<String, String> roots = new HashMap<String, String>();
        roots.put("V:", "A:/bar");
        roots.put("X:", "B:");
        String current = "X:/git";
        NativeFileSystemView view = new NativeFileSystemView("user", roots, current, '/', false);

        assertEquals("X:/git/foo/bar", view.getFile("foo/bar").getAbsolutePath());

        assertEquals("X:/foo/bar", view.getFile("X:/foo/bar").getAbsolutePath());
        assertEquals(new File("B:/foo/bar").toString(), ((NativeSshFile) view.getFile("X:/foo/bar")).getNativeFile().toString());

        assertEquals("X:/foo/bar", view.getFile("../foo/bar").getAbsolutePath());
        assertEquals(new File("B:/foo/bar").toString(), ((NativeSshFile) view.getFile("../foo/bar")).getNativeFile().toString());

        assertEquals("V:/temp", view.getFile("V:/./a/../temp").getAbsolutePath());

        assertEquals("V:/temp", view.getFile("V:/../../temp").getAbsolutePath());
        assertEquals(new File("A:/bar/temp").toString(), ((NativeSshFile) view.getFile("V:/../../temp")).getNativeFile().toString());

        assertEquals("X:/", view.getFile("..").getAbsolutePath());

        SshFile cur = view.getFile(".");
        assertEquals("X:/git", cur.getAbsolutePath());
        cur = view.getFile(cur, "..");
        assertEquals("X:/", cur.getAbsolutePath());


    }
}
