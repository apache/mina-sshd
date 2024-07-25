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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.TreeSet;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests the RootedFileSystemProvider implementation of {@link java.nio.file.spi.FileSystemProvider} checking that
 * permissions for generic FS commands are not permitted outside of the root directory.
 * <p>
 * Individual tests are form pairs (e.g. testX, testXInvalid) where testXInvalid is expected to test a parent path of
 * {@link RootedFileSystem#getRoot()}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class RootedFileSystemProviderTest extends AssertableFile {
    private static final String SKIP_ON_WINDOWS = "Test fails due to windows normalizing paths before opening them, " +
                                                  "allowing one to open a file like \"C:\\directory_doesnt_exist\\..\\myfile.txt\" whereas this is blocked in unix";
    private static final String DOESNT_EXIST = "../doesnt_exist/../";

    private final RootedFileSystem fileSystem;
    private final Path rootSandbox;
    private final FileHelper fileHelper;

    public RootedFileSystemProviderTest() throws Exception {
        super();
        fileHelper = new FileHelper();
        Path targetFolder = Objects.requireNonNull(
                CommonTestSupportUtils.detectTargetFolder(RootedFileSystemProviderTest.class),
                "Failed to detect target folder");
        rootSandbox = fileHelper.createTestSandbox(targetFolder.resolve(TEMP_SUBFOLDER_NAME));
        fileSystem = (RootedFileSystem) new RootedFileSystemProvider().newFileSystem(rootSandbox, Collections.emptyMap());
    }

    @Test
    void root() {
        Path root = fileSystem.getRoot();
        assertTrue(exists(root), "Exists? " + root);
        assertTrue(isDir(root), "Dir? " + root);
        assertTrue(isReadable(root), "Readable? " + root);
        assertTrue(isRootedAt(rootSandbox, root), root + " rooted at " + rootSandbox + " ?");
    }

    /* mkdir */
    @Test
    void mkdir() throws IOException {
        Path created = fileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        try {
            assertTrue(exists(created) && isDir(created) && isReadable(created));
        } finally {
            Files.delete(created);
        }
    }

    @Test
    void mkdirInvalid() {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);

        String parent = DOESNT_EXIST + getCurrentTestName();
        assertThrows(NoSuchFileException.class,
                () -> fileHelper.createDirectory(fileSystem.getPath(parent)),
                String.format("Unexpected success in creating directory %s", parent));
    }

    /* rmdir */
    @Test
    void rmdir() throws IOException {
        Path created = fileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        Path deleted = fileHelper.deleteDirectory(created);
        notExists(deleted);
    }

    @Test
    void rmdirInvalid() throws IOException {
        assertThrows(NoSuchFileException.class, () -> {
            Path deleted = fileHelper.deleteDirectory(fileSystem.getPath(DOESNT_EXIST + getCurrentTestName()));
            fail(String.format("Unexpected success in removing directory %s", deleted.toString()));
        });
    }

    /* chdir */
    @Test
    void chdir() throws IOException {
        Path created = fileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        Path createdFile = fileHelper.createFile(created.resolve(getCurrentTestName()));
        try {
            boolean hasFile = false;
            try (DirectoryStream<Path> ds = fileHelper.readDirectory(created)) {
                for (Path p : ds) {
                    hasFile |= fileHelper.isSameFile(createdFile,
                            fileSystem.getPath(created.getFileName() + "/" + p.getFileName()));
                }
            }
            assertTrue(hasFile, createdFile + " found in ch directory");
        } finally {
            Files.delete(createdFile);
            Files.delete(created);
        }
    }

    /* write */
    @Test
    void writeFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        assertTrue(exists(created) && isReadable(created));
    }

    @Test
    void writeFileInvalid() {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);

        String written = DOESNT_EXIST + getCurrentTestName();
        assertThrows(NoSuchFileException.class,
                () -> fileHelper.createFile(fileSystem.getPath(written)),
                String.format("Unexpected success in writing file %s", written));
    }

    /* read */
    @Test
    void readFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        isNonEmpty(fileHelper.readFile(created));
    }

    @Test
    void readFileInvalid() throws IOException {
        assertThrows(NoSuchFileException.class, () -> {
            Path read = fileSystem.getPath(DOESNT_EXIST + getCurrentTestName());
            fileHelper.readFile(read);
            fail(String.format("Unexpected success in reading file %s", read.toString()));
        });
    }

    /* rm */
    @Test
    void deleteFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path deleted = fileHelper.deleteFile(created);
        notExists(deleted);
    }

    @Test
    void deleteFileInvalid() throws IOException {
        assertThrows(NoSuchFileException.class, () -> {
            Path deleted = fileHelper.deleteFile(fileSystem.getPath(DOESNT_EXIST + getCurrentTestName()));
            fail(String.format("Unexpected success in deleting file %s", deleted.toString()));
        });
    }

    /* cp */
    @Test
    void copyFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path destination = fileSystem.getPath(getCurrentTestName() + "dest");
        try {
            fileHelper.copyFile(created, destination);
            assertTrue(exists(destination) && isReadable(destination));
        } finally {
            Files.delete(destination);
            Files.delete(created);
        }
    }

    @Test
    void copyFileInvalid() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);

        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        String copy = DOESNT_EXIST + getCurrentTestName();
        assertThrows(NoSuchFileException.class,
                () -> fileHelper.copyFile(created, fileSystem.getPath(copy)),
                String.format("Unexpected success in copying file to %s", copy));
    }

    /* mv */
    @Test
    void moveFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path destination = fileSystem.getPath(getCurrentTestName() + "dest");
        fileHelper.moveFile(created, destination);
        assertTrue(notExists(created) && exists(destination) && isReadable(destination));
    }

    @Test
    void moveFileInvalid() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);

        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        String moved = DOESNT_EXIST + getCurrentTestName();
        assertThrows(NoSuchFileException.class,
                () -> fileHelper.moveFile(created, fileSystem.getPath(moved)),
                String.format("Unexpected success in moving file to %s", moved));
    }

    /* link */
    @Test
    void createLink() throws IOException {
        Path existing = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path link = fileSystem.getPath(getCurrentTestName() + "link");
        try {
            fileHelper.createLink(link, existing);
            assertTrue(exists(link) && isReadable(link));
        } finally {
            Files.delete(link);
            Files.delete(existing);
        }
    }

    @Test
    void jailbreakLink() {
        testJailbreakLink("../");
    }

    @Test
    void jailbreakLink2() {
        testJailbreakLink("../test/");
    }

    @Test
    void jailbreakLink3() {
        testJailbreakLink("/..");
    }

    @Test
    void jailbreakLink4() {
        testJailbreakLink("/./..");
    }

    @Test
    void jailbreakLink5() {
        testJailbreakLink("/./../");
    }

    @Test
    void jailbreakLink6() {
        testJailbreakLink("./../");
    }

    @Test
    void jailbreakLink7() {
        String fileName = "/testdir/testdir2/../../..";
        testJailbreakLink(fileName);
    }

    private void testJailbreakLink(String jailbrokenTarget) {
        Path target = fileSystem.getPath(jailbrokenTarget);
        Path linkPath = fileSystem.getPath("/testLink");
        assertThrows(InvalidPathException.class, () -> fileSystem.provider().createSymbolicLink(linkPath, target));
        assertFalse(Files.exists(linkPath));
    }

    @Test
    void createLinkInvalid() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);

        Path existing = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        String link = DOESNT_EXIST + getCurrentTestName() + "link";
        assertThrows(NoSuchFileException.class,
                () -> fileHelper.createLink(fileSystem.getPath(link), existing),
                String.format("Unexpected success in linking file %s", link));
    }

    @Test
    void newByteChannelProviderMismatchException() throws IOException {
        RootedFileSystemProvider provider = new RootedFileSystemProvider();
        Path tempFolder = getTempTargetFolder();
        Path file = Files.createTempFile(tempFolder, getCurrentTestName(), ".txt");
        try (FileSystem fs = provider.newFileSystem(tempFolder, Collections.emptyMap());
             Channel channel = provider.newByteChannel(fs.getPath(file.getFileName().toString()), Collections.emptySet())) {
            assertTrue(channel.isOpen(), "Channel not open");
        }
    }

    @Test
    void resolveRoot() throws IOException {
        Path root = GenericUtils.head(fileSystem.getRootDirectories());
        Path dir = root.resolve("tsd");
        fileHelper.createDirectory(dir);
        Path f1 = fileHelper.createFile(dir.resolve("test.txt"));
        try {
            Path f2;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                f2 = ds.iterator().next();
            }
            assertTrue(f2 instanceof RootedPath, "Unrooted path found");
            assertEquals(f1, f2);
        } finally {
            fileHelper.deleteFile(f1);
            fileHelper.deleteDirectory(dir);
        }
    }

    @Test
    void breakOutOfChroot1() throws IOException {
        String fileName = "../" + getCurrentTestName();
        testBreakOutOfChroot(fileName, fileName);
    }

    @Test
    void breakOutOfChroot2() throws IOException {
        String fileName = "./../" + getCurrentTestName();
        testBreakOutOfChroot(fileName, fileName);
    }

    @Test
    void breakOutOfChroot3() throws IOException {
        String fileName = "/../" + getCurrentTestName();
        testBreakOutOfChroot(fileName, fileName);
    }

    @Test
    void breakOutOfChroot4() throws IOException {
        String fileName = "/.././" + getCurrentTestName();
        testBreakOutOfChroot(fileName, fileName);
    }

    @Test
    void breakOutOfChroot5() throws IOException {
        String fileName = "/./../" + getCurrentTestName();
        testBreakOutOfChroot(fileName, fileName);
    }

    @Test
    void breakOutOfChroot6() throws IOException {
        String fileName = "//../" + getCurrentTestName();
        testBreakOutOfChroot(fileName, "/../" + getCurrentTestName());
    }

    /**
     * Tests to make sure that the attempted break out of the {@code chroot} does not work with the specified filename
     *
     * @param  fileName    the filename to attempt to break out of the {@code chroot} with
     * @param  expected    the expected attempt result
     * @throws IOException on test failure
     */
    private void testBreakOutOfChroot(String fileName, String expected) throws IOException {
        RootedPath breakoutAttempt = fileSystem.getPath(fileName);

        // make sure that our rooted fs behaves like a proper unix fs
        assertEquals(expected, breakoutAttempt.toString());

        Path expectedDir = fileSystem.getRoot().resolve(getCurrentTestName());
        Path newDir = fileHelper.createDirectory(breakoutAttempt);
        try {
            assertTrue(Files.isDirectory(expectedDir));

            String baseName = breakoutAttempt.getName(breakoutAttempt.getNameCount() - 1).toString();
            assertTrue(fileHelper.isSameFile(newDir, fileSystem.getPath(baseName)));

            // make sure we didn't create it one directory out of the jail
            assertFalse(Files.exists(fileSystem.getRoot().resolve("../" + breakoutAttempt.getFileName().toString())));

            // make sure various methods of referencing the file work.
            assertTrue(fileHelper.isSameFile(newDir, fileSystem.getPath("/" + baseName)));
            assertTrue(fileHelper.isSameFile(newDir, fileSystem.getPath("/../../" + baseName)));
            assertTrue(fileHelper.isSameFile(newDir, fileSystem.getPath("./../" + baseName)));
        } finally {
            // cleanup the directory.
            fileHelper.deleteDirectory(newDir);
        }

        assertFalse(Files.isDirectory(expectedDir));
        assertFalse(Files.isDirectory(newDir));
    }

    @Test
    void validSymlink1() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);
        String fileName = "/testdir/../";
        testValidSymlink(fileName, true);
    }

    @Test
    void validSymlink2() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);
        String fileName = "/testdir/testdir2/../";
        testValidSymlink(fileName, true);
    }

    @Test
    void validSymlink3() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);
        String fileName = "/testdir/../testdir3/";
        testValidSymlink(fileName, true);
    }

    @Test
    void validSymlink4() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);
        String fileName = "testdir/../testdir3/../";
        testValidSymlink(fileName, true);
    }

    @Test
    void validSymlink5() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), SKIP_ON_WINDOWS);
        String fileName = "testdir/../testdir3/../testfile";
        testValidSymlink(fileName, false);
    }

    public void testValidSymlink(String symlink, boolean targetIsDirectory) throws IOException {
        Path target = fileSystem.getPath(symlink);
        Path linkPath = fileSystem.getPath("/testLink");
        final List<Path> toDelete = new ArrayList<>();
        try {
            fileSystem.provider().createSymbolicLink(linkPath, target);
            toDelete.add(linkPath);

            // ensure that nothing processed the symlink.
            assertEquals(Paths.get(symlink).toString(),
                    fileSystem.provider().readSymbolicLink(linkPath).toString());
            assertFalse(Files.exists(target));
            assertEquals(Files.exists(linkPath), Files.exists(target));

            // If we don't follow the link, we simply check that the link exists, which it does as we created it.
            assertTrue(Files.exists(linkPath, LinkOption.NOFOLLOW_LINKS));

            createParentDirs(targetIsDirectory ? target : target.getParent(), toDelete);

            if (!targetIsDirectory) {
                Files.createFile(target);
                toDelete.add(target);
            }

            assertTrue(Files.exists(linkPath));
        } finally {
            for (int i = toDelete.size() - 1; i >= 0; i--) {
                Path path = toDelete.get(i);
                try {
                    Files.delete(path);
                } catch (IOException ex) {
                    // ignore as we might try to delete "/dir/.." which will fail as it contains dir..
                }
            }
        }
    }

    private static void createParentDirs(Path target, List<Path> toDelete) throws IOException {
        if (target.getParent() != null) {
            createParentDirs(target.getParent(), toDelete);
        }

        if (!Files.isDirectory(target)) {
            Files.createDirectories(target);
            toDelete.add(target);
        }
    }

    @Test
    void fileNamedSlashOnUnixBasedOS() throws IOException {
        // skip ths test on Win32
        if (!"\\".equals(File.separator)) {
            Path slashFile = fileSystem.getPath("\\");
            Path created = fileHelper.createFile(slashFile);
            try {
                assertTrue(Files.isRegularFile(created));
            } finally {
                fileHelper.deleteFile(created);
            }
        }
    }

    @Test
    void streams() throws IOException {
        byte[] data = "This is test data".getBytes(StandardCharsets.UTF_8);
        RootedPath testPath = fileSystem.getPath("testfile.txt");
        try (OutputStream is = Files.newOutputStream(testPath)) {
            is.write(data);
        }
        byte[] read = new byte[data.length];
        try (InputStream is = Files.newInputStream(testPath)) {
            is.read(read);
        }
        assertArrayEquals(data, read);
    }

    /* Private helper */

    /**
     * Wrapper around the FileSystemProvider to test generic FS related commands. All created temp directories and files
     * used for testing must be deleted in the test which creates them
     */
    @SuppressWarnings("synthetic-access")
    private final class FileHelper {
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
        public Path createTestSandbox(Path tempDir) throws IOException {
            Path path = tempDir.resolve(RootedFileSystemProviderTest.class.getSimpleName());
            Path created = Files.createDirectories(path);
            return created;
        }

        public Path createFile(Path source) throws InvalidPathException, IOException {
            try (FileChannel fc = fileSystem.provider().newFileChannel(source,
                    new TreeSet<>(Arrays.asList(StandardOpenOption.CREATE, StandardOpenOption.WRITE)))) {
                byte[] randomBytes = new byte[1000];
                new Random().nextBytes(randomBytes);
                fc.write(ByteBuffer.wrap(randomBytes));
                return source;
            }
        }

        public Path createLink(Path link, Path existing) throws IOException {
            fileSystem.provider().createLink(link, existing);
            return link;
        }

        public Path createDirectory(Path dir) throws InvalidPathException, IOException {
            fileSystem.provider().createDirectory(dir);
            return dir;
        }

        public Path deleteDirectory(Path dir) throws InvalidPathException, IOException {
            return deleteFile(dir);
        }

        public Path deleteFile(Path source) throws InvalidPathException, IOException {
            fileSystem.provider().delete(source);
            return source;
        }

        public byte[] readFile(Path source) throws IOException {
            try (FileChannel fc = fileSystem.provider().newFileChannel(source,
                    Collections.singleton(StandardOpenOption.READ))) {
                byte[] readBytes = new byte[(int) Files.size(source)];
                fc.read(ByteBuffer.wrap(readBytes));
                return readBytes;
            }
        }

        public Path copyFile(Path source, Path destination) throws InvalidPathException, IOException {
            fileSystem.provider().copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
            return destination;
        }

        public Path moveFile(Path source, Path destination) throws InvalidPathException, IOException {
            fileSystem.provider().move(source, destination, StandardCopyOption.ATOMIC_MOVE);
            return destination;
        }

        public DirectoryStream<Path> readDirectory(Path dir) throws InvalidPathException, IOException {
            DirectoryStream<Path> dirStream = fileSystem.provider().newDirectoryStream(dir, entry -> true);
            return dirStream;
        }

        public boolean isSameFile(Path source, Path destination) throws IOException {
            return fileSystem.provider().isSameFile(source, destination);
        }
    }
}
