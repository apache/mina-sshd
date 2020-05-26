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

package org.apache.sshd.common.file.root;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Random;
import java.util.TreeSet;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * Tests the RootedFileSystemProvider implementation of {@link java.nio.file.spi.FileSystemProvider} checking that
 * permissions for generic FS commands are not permitted outside of the root directory.
 *
 * Individual tests are form pairs (e.g. testX, testXInvalid) where testXInvalid is expected to test a parent path of
 * {@link RootedFileSystem#getRoot()}
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class RootedFileSystemProviderTest extends AssertableFile {
    private static RootedFileSystem fileSystem;
    private static Path rootSandbox;

    public RootedFileSystemProviderTest() {
        super();
    }

    @BeforeClass
    public static void initializeFileSystem() throws IOException {
        Path targetFolder = Objects.requireNonNull(
                CommonTestSupportUtils.detectTargetFolder(RootedFileSystemProviderTest.class),
                "Failed to detect target folder");
        rootSandbox = FileHelper.createTestSandbox(targetFolder.resolve(TEMP_SUBFOLDER_NAME));
        fileSystem = (RootedFileSystem) new RootedFileSystemProvider().newFileSystem(rootSandbox, Collections.emptyMap());
    }

    @Test
    public void testRoot() {
        Path root = fileSystem.getRoot();
        assertTrue("Exists? " + root, exists(root));
        assertTrue("Dir? " + root, isDir(root));
        assertTrue("Readable? " + root, isReadable(root));
        assertTrue(root + " rooted at " + rootSandbox + " ?", isRootedAt(rootSandbox, root));
    }

    /* mkdir */
    @Test
    public void testMkdir() throws IOException {
        Path created = FileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        assertTrue(exists(created) && isDir(created) && isReadable(created));
    }

    @Test(expected = InvalidPathException.class)
    public void testMkdirInvalid() throws IOException {
        Path parent = FileHelper.createDirectory(fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in creating directory %s", parent.toString()));
    }

    /* rmdir */
    @Test
    public void testRmdir() throws IOException {
        Path created = FileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        Path deleted = FileHelper.deleteDirectory(created);
        notExists(deleted);
    }

    @Test(expected = InvalidPathException.class)
    public void testRmdirInvalid() throws IOException {
        Path deleted = FileHelper.deleteDirectory(fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in removing directory %s", deleted.toString()));
    }

    /* chdir */
    @Test
    public void testChdir() throws IOException {
        Path created = FileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        Path createdFile = FileHelper.createFile(created.resolve(getCurrentTestName()));
        boolean hasFile = false;
        try (DirectoryStream<Path> ds = FileHelper.readDirectory(created)) {
            for (Path p : ds) {
                hasFile |= FileHelper.isSameFile(createdFile,
                        fileSystem.getPath(created.getFileName() + "/" + p.getFileName()));
            }
        }
        assertTrue(createdFile + " found in ch directory", hasFile);
    }

    @Test(expected = InvalidPathException.class)
    public void testChdirInvalid() throws IOException {
        Path chdir = FileHelper.createDirectory(fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in changing directory %s", chdir.toString()));
    }

    /* write */
    @Test
    public void testWriteFile() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        assertTrue(exists(created) && isReadable(created));
    }

    @Test(expected = InvalidPathException.class)
    public void testWriteFileInvalid() throws IOException {
        Path written = FileHelper.createFile(fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in writing file %s", written.toString()));
    }

    /* read */
    @Test
    public void testReadFile() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        isNonEmpty(FileHelper.readFile(created));
    }

    @Test(expected = InvalidPathException.class)
    public void testReadFileInvalid() throws IOException {
        Path read = fileSystem.getPath("../" + getCurrentTestName());
        FileHelper.readFile(read);
        fail(String.format("Unexpected success in reading file %s", read.toString()));
    }

    /* rm */
    @Test
    public void testDeleteFile() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path deleted = FileHelper.deleteFile(created);
        notExists(deleted);
    }

    @Test(expected = InvalidPathException.class)
    public void testDeleteFileInvalid() throws IOException {
        Path deleted = FileHelper.deleteFile(fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in deleting file %s", deleted.toString()));
    }

    /* cp */
    @Test
    public void testCopyFile() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path destination = fileSystem.getPath(getCurrentTestName() + "dest");
        FileHelper.copyFile(created, destination);
        assertTrue(exists(destination) && isReadable(destination));
    }

    @Test(expected = InvalidPathException.class)
    public void testCopyFileInvalid() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path copy = FileHelper.copyFile(created, fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in copying file to %s", copy.toString()));
    }

    /* mv */
    @Test
    public void testMoveFile() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path destination = fileSystem.getPath(getCurrentTestName() + "dest");
        FileHelper.moveFile(created, destination);
        assertTrue(notExists(created) && exists(destination) && isReadable(destination));
    }

    @Test(expected = InvalidPathException.class)
    public void testMoveFileInvalid() throws IOException {
        Path created = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path moved = FileHelper.moveFile(created, fileSystem.getPath("../" + getCurrentTestName()));
        fail(String.format("Unexpected success in moving file to %s", moved.toString()));
    }

    /* link */
    @Test
    public void testCreateLink() throws IOException {
        Path existing = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path link = fileSystem.getPath(getCurrentTestName() + "link");
        FileHelper.createLink(link, existing);
        assertTrue(exists(link) && isReadable(link));
    }

    @Test(expected = InvalidPathException.class)
    public void testCreateLinkInvalid() throws IOException {
        Path existing = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path link = FileHelper.createLink(fileSystem.getPath("../" + getCurrentTestName() + "link"), existing);
        fail(String.format("Unexpected success in linking file %s", link.toString()));
    }

    @Test
    public void testNewByteChannelProviderMismatchException() throws IOException {
        RootedFileSystemProvider provider = new RootedFileSystemProvider();
        Path tempFolder = assertHierarchyTargetFolderExists(getTempTargetFolder());
        Path file = Files.createTempFile(tempFolder, getCurrentTestName(), ".txt");
        try (FileSystem fs = provider.newFileSystem(tempFolder, Collections.emptyMap());
             Channel channel = provider.newByteChannel(fs.getPath(file.getFileName().toString()), Collections.emptySet())) {
            assertTrue("Channel not open", channel.isOpen());
        }
    }

    @Test
    public void testResolveRoot() throws IOException {
        Path root = GenericUtils.head(fileSystem.getRootDirectories());
        Path dir = root.resolve("tsd");
        FileHelper.createDirectory(dir);
        Path f1 = FileHelper.createFile(dir.resolve("test.txt"));
        Path f2 = Files.newDirectoryStream(dir).iterator().next();
        assertTrue("Unrooted path found", f2 instanceof RootedPath);
        assertEquals(f1, f2);
        FileHelper.deleteFile(f1);
        FileHelper.deleteDirectory(dir);
    }

    /* Private helper */

    /**
     * Wrapper around the FileSystemProvider to test generic FS related commands. All created temp directories and files
     * used for testing are deleted upon JVM exit.
     */
    @SuppressWarnings("synthetic-access")
    private static final class FileHelper {
        private FileHelper() {
            super();
        }

        /**
         * Create a randomized test sandbox on each test execution
         *
         * @param  tempDir     location to create the sandbox
         * @return             the created sandbox Path
         * @throws IOException on failure to create
         */
        public static Path createTestSandbox(Path tempDir) throws IOException {
            Path created = Files.createDirectories(tempDir.resolve(RootedFileSystemProviderTest.class.getSimpleName()));
            created.toFile().deleteOnExit();
            return created;
        }

        public static Path createFile(Path source) throws InvalidPathException, IOException {
            try (FileChannel fc = fileSystem.provider().newFileChannel(source,
                    new TreeSet<OpenOption>(Arrays.asList(StandardOpenOption.CREATE, StandardOpenOption.WRITE)))) {
                byte[] randomBytes = new byte[1000];
                new Random().nextBytes(randomBytes);
                fc.write(ByteBuffer.wrap(randomBytes));
                source.toFile().deleteOnExit();
                return source;
            }
        }

        public static Path createLink(Path link, Path existing) throws IOException {
            fileSystem.provider().createLink(link, existing);
            link.toFile().deleteOnExit();
            return link;
        }

        public static Path createDirectory(Path dir) throws InvalidPathException, IOException {
            fileSystem.provider().createDirectory(dir);
            dir.toFile().deleteOnExit();
            return dir;
        }

        public static Path deleteDirectory(Path dir) throws InvalidPathException, IOException {
            return deleteFile(dir);
        }

        public static Path deleteFile(Path source) throws InvalidPathException, IOException {
            fileSystem.provider().delete(source);
            return source;
        }

        public static byte[] readFile(Path source) throws IOException {
            try (FileChannel fc = fileSystem.provider().newFileChannel(source,
                    new TreeSet<OpenOption>(Arrays.asList(StandardOpenOption.READ)))) {
                byte[] readBytes = new byte[(int) source.toFile().length()];
                fc.read(ByteBuffer.wrap(readBytes));
                return readBytes;
            }
        }

        public static Path copyFile(Path source, Path destination) throws InvalidPathException, IOException {
            fileSystem.provider().copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
            destination.toFile().deleteOnExit();
            return destination;
        }

        public static Path moveFile(Path source, Path destination) throws InvalidPathException, IOException {
            fileSystem.provider().move(source, destination, StandardCopyOption.ATOMIC_MOVE);
            destination.toFile().deleteOnExit();
            return destination;
        }

        public static DirectoryStream<Path> readDirectory(Path dir) throws InvalidPathException, IOException {
            DirectoryStream<Path> dirStream = fileSystem.provider().newDirectoryStream(dir, entry -> true);
            return dirStream;
        }

        public static boolean isSameFile(Path source, Path destination) throws IOException {
            return fileSystem.provider().isSameFile(source, destination);
        }
    }
}
