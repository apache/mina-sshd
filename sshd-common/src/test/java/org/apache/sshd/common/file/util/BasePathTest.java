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
package org.apache.sshd.common.file.util;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
@SuppressWarnings("checkstyle:MethodCount")
public class BasePathTest extends JUnitTestSupport {
    private TestFileSystem fileSystem;

    public BasePathTest() {
        super();
    }

    @Before
    public void setUp() {
        fileSystem = new TestFileSystem(Mockito.mock(FileSystemProvider.class));
    }

    @Test
    public void testBasicPathParsing() {
        assertPathEquals("/", "/");
        assertPathEquals("/foo", "/foo");
        assertPathEquals("/foo", "/", "foo");
        assertPathEquals("/foo/bar", "/foo/bar");
        assertPathEquals("/foo/bar", "/", "foo", "bar");
        assertPathEquals("/foo/bar", "/foo", "bar");
        assertPathEquals("/foo/bar", "/", "foo/bar");
        assertPathEquals("foo/bar/baz", "foo/bar/baz");
        assertPathEquals("foo/bar/baz", "foo", "bar", "baz");
        assertPathEquals("foo/bar/baz", "foo/bar", "baz");
        assertPathEquals("foo/bar/baz", "foo", "bar/baz");
    }

    @Test
    public void testPathParsingWithExtraSeparators() {
        assertPathEquals("/foo/bar", "///foo/bar");
        assertPathEquals("/foo/bar", "/foo///bar//");
        assertPathEquals("/foo/bar/baz", "/foo", "/bar", "baz/");
        // assertPathEquals("/foo/bar/baz", "/foo\\/bar//\\\\/baz\\/");
    }

    @Test
    public void testRootPath() {
        new PathTester(fileSystem, "/")
                .root("/")
                .test("/");
    }

    @Test
    public void testRelativePathSingleName() {
        new PathTester(fileSystem, "test")
                .names("test")
                .test("test");

        Path path = parsePath("test");
        assertEquals(path, path.getFileName());
    }

    @Test
    public void testRelativePathTwoNames() {
        new PathTester(fileSystem, "foo/bar")
                .names("foo", "bar")
                .test("foo/bar");
    }

    @Test
    public void testRelativePathFourNames() {
        new PathTester(fileSystem, "foo/bar/baz/test")
                .names("foo", "bar", "baz", "test")
                .test("foo/bar/baz/test");
    }

    @Test
    public void testAbsolutePathSingleName() {
        new PathTester(fileSystem, "/foo")
                .root("/")
                .names("foo")
                .test("/foo");
    }

    @Test
    public void testAbsolutePathTwoNames() {
        new PathTester(fileSystem, "/foo/bar")
                .root("/")
                .names("foo", "bar")
                .test("/foo/bar");
    }

    @Test
    public void testAbsoluteMultiNamePathFourNames() {
        new PathTester(fileSystem, "/foo/bar/baz/test")
                .root("/")
                .names("foo", "bar", "baz", "test")
                .test("/foo/bar/baz/test");
    }

    @Test
    public void testResolveFromRoot() {
        Path root = parsePath("/");
        assertResolvedPathEquals("/foo", root, "foo");
        assertResolvedPathEquals("/foo/bar", root, "foo/bar");
        assertResolvedPathEquals("/foo/bar", root, "foo", "bar");
        assertResolvedPathEquals("/foo/bar/baz/test", root, "foo/bar/baz/test");
        assertResolvedPathEquals("/foo/bar/baz/test", root, "foo", "bar/baz", "test");
    }

    @Test
    public void testResolveFromAbsolute() {
        Path path = parsePath("/foo");
        assertResolvedPathEquals("/foo/bar", path, "bar");
        assertResolvedPathEquals("/foo/bar/baz/test", path, "bar/baz/test");
        assertResolvedPathEquals("/foo/bar/baz/test", path, "bar/baz", "test");
        assertResolvedPathEquals("/foo/bar/baz/test", path, "bar", "baz", "test");
    }

    @Test
    public void testResolveFromRelative() {
        Path path = parsePath("foo");
        assertResolvedPathEquals("foo/bar", path, "bar");
        assertResolvedPathEquals("foo/bar/baz/test", path, "bar/baz/test");
        assertResolvedPathEquals("foo/bar/baz/test", path, "bar", "baz", "test");
        assertResolvedPathEquals("foo/bar/baz/test", path, "bar/baz", "test");
    }

    @Test
    public void testResolveWithThisAndParentDirNames() {
        Path path = parsePath("/foo");
        assertResolvedPathEquals("/foo/bar/../baz", path, "bar/../baz");
        assertResolvedPathEquals("/foo/bar/../baz", path, "bar", "..", "baz");
        assertResolvedPathEquals("/foo/./bar/baz", path, "./bar/baz");
        assertResolvedPathEquals("/foo/./bar/baz", path, ".", "bar/baz");
    }

    @Test
    public void testResolveGivenAbsolutePath() {
        assertResolvedPathEquals("/test", parsePath("/foo"), "/test");
        assertResolvedPathEquals("/test", parsePath("foo"), "/test");
    }

    @Test
    public void testResolveGivenEmptyPath() {
        assertResolvedPathEquals("/foo", parsePath("/foo"), "");
        assertResolvedPathEquals("foo", parsePath("foo"), "");
    }

    @Test
    public void testResolveAgainstEmptyPath() {
        assertResolvedPathEquals("foo/bar", parsePath(""), "foo/bar");
    }

    @Test
    public void testResolveSiblingGivenEmptyPath() {
        Path path = parsePath("foo/bar");
        Path resolved = path.resolveSibling("");
        assertPathEquals("foo", resolved);

        path = parsePath("foo");
        resolved = path.resolveSibling("");
        assertPathEquals("", resolved);
    }

    @Test
    public void testResolveSiblingAgainstEmptyPath() {
        Path path = parsePath("");
        Path resolved = path.resolveSibling("foo");
        assertPathEquals("foo", resolved);

        path = parsePath("");
        resolved = path.resolveSibling("");
        assertPathEquals("", resolved);
    }

    @Test
    public void testRelativizeBothAbsolute() {
        assertRelativizedPathEquals("b/c", parsePath("/a"), "/a/b/c");
        assertRelativizedPathEquals("c/d", parsePath("/a/b"), "/a/b/c/d");
    }

    @Test
    public void testRelativizeBothRelative() {
        assertRelativizedPathEquals("b/c", parsePath("a"), "a/b/c");
        assertRelativizedPathEquals("d", parsePath("a/b/c"), "a/b/c/d");
    }

    @Test
    public void testRelativizeAgainstEmptyPath() {
        assertRelativizedPathEquals("foo/bar", parsePath(""), "foo/bar");
    }

    @Test
    public void testRelativizeOneAbsoluteOneRelative() {
        try {
            Path result = parsePath("/foo/bar").relativize(parsePath("foo"));
            fail("Unexpected 2-level result: " + result);
        } catch (IllegalArgumentException expected) {
            // ignored
        }

        try {
            Path result = parsePath("foo").relativize(parsePath("/foo/bar"));
            fail("Unexpected 1-level result: " + result);
        } catch (IllegalArgumentException expected) {
            // ignored
        }
    }

    @Test
    public void testNormalizeWithParentDirName() {
        assertNormalizedPathEquals("/foo/baz", "/foo/bar/../baz");
        assertNormalizedPathEquals("/foo/baz", "/foo", "bar", "..", "baz");
    }

    @Test
    public void testNormalizeWithThisDirName() {
        assertNormalizedPathEquals("/foo/bar/baz", "/foo/bar/./baz");
        assertNormalizedPathEquals("/foo/bar/baz", "/foo", "bar", ".", "baz");
    }

    @Test
    public void testNormalizeWithThisAndParentDirNames() {
        assertNormalizedPathEquals("foo/test", "foo/./bar/../././baz/../test");
    }

    @Test
    public void testNormalizeWithLeadingParentDirNames() {
        assertNormalizedPathEquals("../../foo/baz", "../../foo/bar/../baz");
    }

    @Test
    public void testNormalizeWithLeadingThisAndParentDirNames() {
        assertNormalizedPathEquals("../../foo/baz", "./.././.././foo/bar/../baz");
    }

    @Test
    public void testNormalizeWithExtraParentDirNamesAtRoot() {
        assertNormalizedPathEquals("/", "/..");
        assertNormalizedPathEquals("/", "/../../..");
        assertNormalizedPathEquals("/", "/foo/../../..");
        assertNormalizedPathEquals("/", "/../foo/../../bar/baz/../../../..");
    }

    @Test
    public void testPathWithExtraSlashes() {
        assertPathEquals("/foo/bar/baz", parsePath("/foo/bar/baz/"));
        assertPathEquals("/foo/bar/baz", parsePath("/foo//bar///baz"));
        assertPathEquals("/foo/bar/baz", parsePath("///foo/bar/baz"));
    }

    private void assertResolvedPathEquals(
            String expected, Path path, String firstResolvePath, String... moreResolvePaths) {
        Path resolved = path.resolve(firstResolvePath);
        for (String additionalPath : moreResolvePaths) {
            resolved = resolved.resolve(additionalPath);
        }
        assertPathEquals(expected, resolved);

        Path relative = parsePath(firstResolvePath, moreResolvePaths);
        resolved = path.resolve(relative);
        assertPathEquals(expected, resolved);

        // assert the invariant that p.relativize(p.resolve(q)).equals(q) when q does not have a root
        // p = path, q = relative, p.resolve(q) = resolved
        if (relative.getRoot() == null) {
            assertEquals(relative, path.relativize(resolved));
        }
    }

    private void assertRelativizedPathEquals(String expected, Path path, String relativizePath) {
        Path relativized = path.relativize(parsePath(relativizePath));
        assertPathEquals(expected, relativized);
    }

    private void assertNormalizedPathEquals(String expected, String first, String... more) {
        assertPathEquals(expected, parsePath(first, more).normalize());
    }

    private void assertPathEquals(String expected, String first, String... more) {
        assertPathEquals(expected, parsePath(first, more));
    }

    private void assertPathEquals(String expected, Path path) {
        assertEquals(parsePath(expected), path);
    }

    private Path parsePath(String first, String... more) {
        return fileSystem.getPath(first, more);
    }

    private static class TestFileSystem extends BaseFileSystem<TestPath> {
        TestFileSystem(FileSystemProvider fileSystemProvider) {
            super(fileSystemProvider);
        }

        @Override
        protected TestPath create(String root, List<String> names) {
            return new TestPath(this, root, names);
        }

        @Override
        public void close() throws IOException {
            // ignored
        }

        @Override
        public boolean isOpen() {
            return false;
        }

        @Override
        public Set<String> supportedFileAttributeViews() {
            return null;
        }

        @Override
        public UserPrincipalLookupService getUserPrincipalLookupService() {
            return null;
        }
    }

    private static class TestPath extends BasePath<TestPath, TestFileSystem> {
        TestPath(TestFileSystem fileSystem, String root, List<String> names) {
            super(fileSystem, root, names);
        }

        @Override
        protected TestPath create(String root, List<String> names) {
            return new TestPath(getFileSystem(), root, names);
        }

        @Override
        public URI toUri() {
            return null;
        }

        @Override
        public Path toRealPath(LinkOption... options) throws IOException {
            return null;
        }
    }

    public static class PathTester {
        private final FileSystem fileSystem;
        private final String string;
        private String root;
        private List<String> names = Collections.emptyList();

        public PathTester(FileSystem fileSystem, String string) {
            this.fileSystem = fileSystem;
            this.string = string;
        }

        public PathTester root(String root) {
            this.root = root;
            return this;
        }

        public PathTester names(Collection<String> names) {
            this.names = GenericUtils.unmodifiableList(names);
            return this;
        }

        public PathTester names(String... names) {
            return names(Arrays.asList(names));
        }

        public void test(String first, String... more) {
            Path path = fileSystem.getPath(first, more);
            test(path);
        }

        public void test(Path path) {
            assertEquals("Mismatched path value", string, path.toString());

            testRoot(path);
            testNames(path);
            testParents(path);
            testStartsWith(path);
            testEndsWith(path);
            testSubpaths(path);
        }

        protected void testRoot(Path path) {
            if (root != null) {
                assertTrue(path + ".isAbsolute() ?", path.isAbsolute());
                assertNotNull(path + ".getRoot() <> null ?", path.getRoot());
                assertEquals("Mismatched root path value", root, path.getRoot().toString());
            } else {
                assertFalse(path + ".is(Not)Absolute() ?", path.isAbsolute());
                assertNull(path + ".getRoot() == null ?", path.getRoot());
            }
        }

        protected void testNames(Path path) {
            assertEquals("Mismatched names count", names.size(), path.getNameCount());
            assertListEquals("Mismatched path names", names, names(path));

            for (int i = 0; i < names.size(); i++) {
                String nameAtIndex = names.get(i);
                Path pathAtIndex = path.getName(i);
                assertEquals("Mismatched component name at index=" + i, nameAtIndex, pathAtIndex.toString());
                // don't test individual names if this is an individual name
                if (names.size() > 1) {
                    new PathTester(fileSystem, nameAtIndex)
                            .names(nameAtIndex)
                            .test(pathAtIndex);
                }
            }

            if (names.size() > 0) {
                String fileName = names.get(names.size() - 1);
                assertEquals("Mismatched last component name", fileName, path.getFileName().toString());
                // don't test individual names if this is an individual name
                if (names.size() > 1) {
                    new PathTester(fileSystem, fileName)
                            .names(fileName)
                            .test(path.getFileName());
                }
            }
        }

        protected void testParents(Path path) {
            Path parent = path.getParent();
            if (((root != null) && (names.size() >= 1)) || (names.size() > 1)) {
                assertNotNull("No parent", parent);
            }

            if (parent != null) {
                String parentName = names.size() == 1 ? root : string.substring(0, string.lastIndexOf('/'));
                new PathTester(fileSystem, parentName)
                        .root(root)
                        .names(names.subList(0, names.size() - 1))
                        .test(parent);
            }
        }

        protected void testSubpaths(Path path) {
            int nameCount = path.getNameCount();
            if (path.getRoot() == null) {
                assertEquals(path, path.subpath(0, nameCount));
            }

            if (nameCount > 1) {
                String stringWithoutRoot = root == null ? string : string.substring(root.length());

                // test start + 1 to end and start to end - 1 subpaths... this recursively tests all subpaths
                // actually tests most possible subpaths multiple times but... eh
                Path startSubpath = path.subpath(1, nameCount);
                List<String> startNames = split(stringWithoutRoot, '/')
                        .subList(1, nameCount);
                new PathTester(fileSystem, GenericUtils.join(startNames, '/'))
                        .names(startNames)
                        .test(startSubpath);

                Path endSubpath = path.subpath(0, nameCount - 1);
                List<String> endNames = split(stringWithoutRoot, '/')
                        .subList(0, nameCount - 1);
                new PathTester(fileSystem, GenericUtils.join(endNames, '/'))
                        .names(endNames)
                        .test(endSubpath);
            }
        }

        protected void testStartsWith(Path path) {
            // empty path doesn't start with any path
            if ((root != null) || (!names.isEmpty())) {
                Path other = path;
                while (other != null) {
                    assertTrue(path + ".startsWith(" + other + ")[path] ?", path.startsWith(other));
                    assertTrue(path + ".startsWith(" + other + ")[string] ?", path.startsWith(other.toString()));
                    other = other.getParent();
                }
            }
        }

        protected void testEndsWith(Path path) {
            // empty path doesn't start with any path
            if ((root != null) || (!names.isEmpty())) {
                Path other = path;
                while (other != null) {
                    assertTrue(path + ".endsWith(" + other + ")[path] ?", path.endsWith(other));
                    assertTrue(path + ".endsWith(" + other + ")[string] ?", path.endsWith(other.toString()));

                    int otherNameCount = other.getNameCount();
                    if ((other.getRoot() != null) && (otherNameCount > 0)) {
                        other = other.subpath(0, otherNameCount);
                    } else if (otherNameCount > 1) {
                        other = other.subpath(1, otherNameCount);
                    } else {
                        other = null;
                    }
                }
            }
        }

        private static List<String> names(Path path) {
            List<String> list = new ArrayList<>();
            for (Path p : path) {
                list.add(p.toString());
            }
            return list;
        }

        private static List<String> split(String string, char sep) {
            return Arrays.asList(GenericUtils.split(string, sep));
        }
    }
}
