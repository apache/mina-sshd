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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.TreeSet;
import java.util.function.Supplier;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;

/**
 * Tests the RootedFileSystemProvider implementation of {@link java.nio.file.spi.FileSystemProvider} checking that
 * permissions for generic FS commands are not permitted outside of the root directory.
 * <p>
 * Individual tests are form pairs (e.g. testX, testXInvalid) where testXInvalid is expected to test a parent path of
 * {@link RootedFileSystem#getRoot()}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
@RunWith(Parameterized.class)
public class RootedFileSystemProviderTest extends AssertableFile {
    private static final String DOESNT_EXIST = "../doesnt_exist/../";

    private static FileSystem unixInMemFs;
    private static FileSystem windowsInMemFs;
    private static FileSystem osxInMemFs;
    private final FileSystem hostFilesystem;
    private final RootedFileSystem fileSystem;
    private final Path rootSandbox;
    private final FileHelper fileHelper;
    private final boolean isTestingRealWindowsHostFS;

    public RootedFileSystemProviderTest(String fsType, Supplier<FileSystem> hostFilesystem) throws Exception {
        super();

        this.hostFilesystem = hostFilesystem.get();
        Path targetFolder = Objects.requireNonNull(
                CommonTestSupportUtils.detectTargetFolder(RootedFileSystemProviderTest.class),
                "Failed to detect target folder");
        Path targetFolderOnHostFs = getTargetFolderOnHostFs(targetFolder);
        fileHelper = new FileHelper();
        rootSandbox = fileHelper.createTestSandbox(targetFolderOnHostFs.resolve(TEMP_SUBFOLDER_NAME));
        fileSystem = (RootedFileSystem) new RootedFileSystemProvider().newFileSystem(rootSandbox, Collections.emptyMap());
        this.isTestingRealWindowsHostFS = OsUtils.isWin32() && this.hostFilesystem == FileSystems.getDefault();
    }

    @Parameterized.Parameters(name = "{0}FS")
    public static Collection<Object[]> data() {
        return Arrays.asList(
                new Object[] { "Windows", (Supplier<FileSystem>) () -> windowsInMemFs },
                new Object[] { "Unix", (Supplier<FileSystem>) () -> unixInMemFs },
                new Object[] { "MacOS", (Supplier<FileSystem>) () -> osxInMemFs },
                new Object[] { "Native", (Supplier<FileSystem>) FileSystems::getDefault });
    }

    @BeforeClass
    public static void initializeFileSystem() {
        unixInMemFs = Jimfs.newFileSystem(Configuration.unix());
        windowsInMemFs = Jimfs.newFileSystem(Configuration.windows());
        osxInMemFs = Jimfs.newFileSystem(Configuration.osX());
    }

    @AfterClass
    public static void afterClass() {
        List<Exception> failures = new ArrayList<>();
        for (FileSystem fs : Arrays.asList(unixInMemFs, windowsInMemFs, osxInMemFs)) {
            try {
                fs.close();
            } catch (Exception ex) {
                failures.add(ex);
            }
        }
        Assert.assertEquals(Collections.emptyList(), failures);
    }

    private Path getTargetFolderOnHostFs(Path targetFolder) {
        // need to reroot a file for a unix file system on windows
        if (this.hostFilesystem.getSeparator().equals("/") && targetFolder.getRoot() != null
                && targetFolder.getRoot().toString().contains(":")) {
            return reroot(this.hostFilesystem.getSeparator(), targetFolder);
        }
        // need to reroot a file for a windows file system on unix
        if (this.hostFilesystem.getSeparator().equals("\\") && targetFolder.getRoot() != null
                && "/".equals(targetFolder.getRoot().toString())) {
            // Note: Even though the hard coded "C:\\" looks suspicious, it is OK, as this code ONLY runs on Unix
            // based systems for the JimFs tests that use a windows fs.
            return reroot("C:\\", targetFolder);
        }
        return this.hostFilesystem.getPath(targetFolder.toString());
    }

    private Path reroot(String newRoot, Path targetFolder) {
        String[] parts = new String[targetFolder.getNameCount() - 1];
        for (int i = 1; i <= parts.length; i++) {
            parts[i - 1] = targetFolder.getName(i).toString();
        }
        return this.hostFilesystem.getPath(newRoot, parts);
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
        Path created = fileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        try {
            assertTrue(exists(created) && isDir(created) && isReadable(created));
        } finally {
            Files.delete(created);
        }
    }

    @Test
    public void testMkdirInvalid() {
        if (isTestingRealWindowsHostFS) {
            return;
        }

        String parent = DOESNT_EXIST + getCurrentTestName();
        assertThrows(String.format("Unexpected success in creating directory %s", parent), NoSuchFileException.class,
                () -> fileHelper.createDirectory(fileSystem.getPath(parent)));
    }

    /* rmdir */
    @Test
    public void testRmdir() throws IOException {
        Path created = fileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
        Path deleted = fileHelper.deleteDirectory(created);
        notExists(deleted);
    }

    @Test(expected = NoSuchFileException.class)
    public void testRmdirInvalid() throws IOException {
        Path deleted = fileHelper.deleteDirectory(fileSystem.getPath(DOESNT_EXIST + getCurrentTestName()));
        fail(String.format("Unexpected success in removing directory %s", deleted.toString()));
    }

    /* chdir */
    @Test
    public void testChdir() throws IOException {
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
            assertTrue(createdFile + " found in ch directory", hasFile);
        } finally {
            Files.delete(createdFile);
            Files.delete(created);
        }
    }

    @Test
    public void testChdirInvalid() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }

        String chdir = DOESNT_EXIST + getCurrentTestName();
        assertThrows(String.format("Unexpected success in changing directory %s", chdir),
                NoSuchFileException.class, () -> fileHelper.createDirectory(fileSystem.getPath(chdir)));
    }

    /* write */
    @Test
    public void testWriteFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        assertTrue(exists(created) && isReadable(created));
    }

    @Test
    public void testWriteFileInvalid() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }

        String written = DOESNT_EXIST + getCurrentTestName();
        assertThrows(String.format("Unexpected success in writing file %s", written), NoSuchFileException.class,
                () -> fileHelper.createFile(fileSystem.getPath(written)));
    }

    /* read */
    @Test
    public void testReadFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        isNonEmpty(fileHelper.readFile(created));
    }

    @Test(expected = NoSuchFileException.class)
    public void testReadFileInvalid() throws IOException {
        Path read = fileSystem.getPath(DOESNT_EXIST + getCurrentTestName());
        fileHelper.readFile(read);
        fail(String.format("Unexpected success in reading file %s", read.toString()));
    }

    /* rm */
    @Test
    public void testDeleteFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path deleted = fileHelper.deleteFile(created);
        notExists(deleted);
    }

    @Test(expected = NoSuchFileException.class)
    public void testDeleteFileInvalid() throws IOException {
        Path deleted = fileHelper.deleteFile(fileSystem.getPath(DOESNT_EXIST + getCurrentTestName()));
        fail(String.format("Unexpected success in deleting file %s", deleted.toString()));
    }

    /* cp */
    @Test
    public void testCopyFile() throws IOException {
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
    public void testCopyFileInvalid() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        String copy = DOESNT_EXIST + getCurrentTestName();
        assertThrows(String.format("Unexpected success in copying file to %s", copy),
                NoSuchFileException.class,
                () -> fileHelper.copyFile(created, fileSystem.getPath(copy)));
    }

    /* mv */
    @Test
    public void testMoveFile() throws IOException {
        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        Path destination = fileSystem.getPath(getCurrentTestName() + "dest");
        fileHelper.moveFile(created, destination);
        assertTrue(notExists(created) && exists(destination) && isReadable(destination));
    }

    @Test
    public void testMoveFileInvalid() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }

        Path created = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        String moved = DOESNT_EXIST + getCurrentTestName();
        assertThrows(String.format("Unexpected success in moving file to %s", moved), NoSuchFileException.class,
                () -> fileHelper.moveFile(created, fileSystem.getPath(moved)));
    }

    /* link */
    @Test
    public void testCreateLink() throws IOException {
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
    public void testJailbreakLink() throws IOException {
        testJailbreakLink("../");
    }

    @Test
    public void testJailbreakLink2() throws IOException {
        testJailbreakLink("../test/");
    }

    @Test
    public void testJailbreakLink3() throws IOException {
        testJailbreakLink("/..");
    }

    @Test
    public void testJailbreakLink4() throws IOException {
        testJailbreakLink("/./..");
    }

    @Test
    public void testJailbreakLink5() throws IOException {
        testJailbreakLink("/./../");
    }

    @Test
    public void testJailbreakLink6() throws IOException {
        testJailbreakLink("./../");
    }

    @Test
    public void testJailbreakLink7() throws IOException {
        String fileName = "/testdir/testdir2/../../..";
        testJailbreakLink(fileName);
    }

    private void testJailbreakLink(String jailbrokenTarget) throws IOException {
        Path target = fileSystem.getPath(jailbrokenTarget);
        Path linkPath = fileSystem.getPath("/testLink");
        Assert.assertThrows(InvalidPathException.class, () -> fileSystem.provider().createSymbolicLink(linkPath, target));
        Assert.assertFalse(Files.exists(linkPath));
    }

    @Test
    public void testCreateLinkInvalid() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
        Path existing = fileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
        String link = DOESNT_EXIST + getCurrentTestName() + "link";
        assertThrows(String.format("Unexpected success in linking file %s", link), NoSuchFileException.class,
                () -> fileHelper.createLink(fileSystem.getPath(link), existing));
    }

    @Test
    public void testNewByteChannelProviderMismatchException() throws IOException {
        RootedFileSystemProvider provider = new RootedFileSystemProvider();
        Path tempFolder = getTargetFolderOnHostFs(getTempTargetFolder());
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
        fileHelper.createDirectory(dir);
        Path f1 = fileHelper.createFile(dir.resolve("test.txt"));
        try {
            Path f2;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                f2 = ds.iterator().next();
            }
            assertTrue("Unrooted path found", f2 instanceof RootedPath);
            assertEquals(f1, f2);
        } finally {
            fileHelper.deleteFile(f1);
            fileHelper.deleteDirectory(dir);
        }
    }

    @Test
    public void testBreakOutOfChroot1() throws IOException {
        String fileName = "../" + getCurrentTestName();
        testBreakOutOfChroot(fileName);
    }

    @Test
    public void testBreakOutOfChroot2() throws IOException {
        String fileName = "./../" + getCurrentTestName();
        testBreakOutOfChroot(fileName);
    }

    @Test
    public void testBreakOutOfChroot3() throws IOException {
        String fileName = "/../" + getCurrentTestName();
        testBreakOutOfChroot(fileName);
    }

    @Test
    public void testBreakOutOfChroot4() throws IOException {
        String fileName = "/.././" + getCurrentTestName();
        testBreakOutOfChroot(fileName);
    }

    @Test
    public void testBreakOutOfChroot5() throws IOException {
        String fileName = "/./../" + getCurrentTestName();
        testBreakOutOfChroot(fileName);
    }

    @Test
    public void testBreakOutOfChroot6() throws IOException {
        String fileName = "//../" + getCurrentTestName();
        testBreakOutOfChroot(fileName);
    }

    /**
     * Tests to make sure that the attempted break out of the chroot does not work with the specified filename
     *
     * @param  fileName    the filename to attempt to break out of the chroot with
     * @throws IOException on test failure
     */
    private void testBreakOutOfChroot(String fileName) throws IOException {
        RootedPath breakoutAttempt = fileSystem.getPath(fileName);

        // make sure that our rooted fs behaves like a proper unix fs
        Assert.assertEquals(unixInMemFs.getPath(fileName).toString(), breakoutAttempt.toString());

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
    public void testValidSymlink1() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
        String fileName = "/testdir/../";
        testValidSymlink(fileName, true);
    }

    @Test
    public void testValidSymlink2() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
        String fileName = "/testdir/testdir2/../";
        testValidSymlink(fileName, true);
    }

    @Test
    public void testValidSymlink3() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
        String fileName = "/testdir/../testdir3/";
        testValidSymlink(fileName, true);
    }

    @Test
    public void testValidSymlink4() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
        String fileName = "testdir/../testdir3/../";
        testValidSymlink(fileName, true);
    }

    @Test
    public void testValidSymlink5() throws IOException {
        if (isTestingRealWindowsHostFS) {
            return;
        }
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
            Assert.assertEquals(unixInMemFs.getPath(symlink).toString(),
                    fileSystem.provider().readSymbolicLink(linkPath).toString());
            Assert.assertFalse(Files.exists(target));
            Assert.assertEquals(Files.exists(linkPath), Files.exists(target));

            // If we don't follow the link, we simply check that the link exists, which it does as we created it.
            Assert.assertTrue(Files.exists(linkPath, LinkOption.NOFOLLOW_LINKS));

            createParentDirs(targetIsDirectory ? target : target.getParent(), toDelete);

            if (!targetIsDirectory) {
                Files.createFile(target);
                toDelete.add(target);
            }

            Assert.assertTrue(Files.exists(linkPath));
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
    public void testFileNamedSlashOnUnixBasedOS() throws IOException {
        // skip ths test on Win32
        if (!"\\".equals(hostFilesystem.getSeparator())) {
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
    public void testStreams() throws IOException {
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
            Path created = Files.createDirectories(tempDir.resolve(RootedFileSystemProviderTest.class.getSimpleName()));
            return created;
        }

        public Path createFile(Path source) throws InvalidPathException, IOException {
            try (FileChannel fc = fileSystem.provider().newFileChannel(source,
                    new TreeSet<OpenOption>(Arrays.asList(StandardOpenOption.CREATE, StandardOpenOption.WRITE)))) {
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
