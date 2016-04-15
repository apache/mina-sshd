package org.apache.sshd.common.file.root;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;


/**
 * Tests the RootedFileSystemProvider implementation of {@link java.nio.file.spi.FileSystemProvider}
 * checking that permissions for generic FS commands are not permitted outside of the
 * root directory.
 *
 * Individual tests are form pairs (e.g. testX, testXInvalid) where testXInvalid is
 * expected to test a parent path of {@link RootedFileSystem#getRoot()}
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RootedFileSystemProviderTest extends AssertableFile {

  private static RootedFileSystem fileSystem;
  private static Path rootSandbox;

  public RootedFileSystemProviderTest() {
    super();
  }

  @BeforeClass
  public static void onlyOnce() throws IOException {
    rootSandbox = FileHelper.createTestSandbox();
    fileSystem = (RootedFileSystem) new RootedFileSystemProvider()
        .newFileSystem(rootSandbox, Collections.<String, Object>emptyMap());
  }

  @Test
  public void testRoot() {
    assertTrue(isFile(fileSystem.getRoot()) &&
        isDir(fileSystem.getRoot()) &&
        isReadable(fileSystem.getRoot()) &&
        isRootedAt(rootSandbox, fileSystem.getRoot()));
  }

  /* mkdir */
  @Test
  public void testMkdir() throws IOException {
    Path created = FileHelper.createDirectory(fileSystem.getPath(getCurrentTestName()));
    assertTrue(isFile(created) && isDir(created) && isReadable(created));
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
    try(DirectoryStream<Path> ds = FileHelper.readDirectory(created)) {
      for (Path p : ds) {
        hasFile |= FileHelper.isSameFile(createdFile, fileSystem.getPath(created.getFileName() + "/" + p.getFileName()));
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
    assertTrue(isFile(created) && isReadable(created));
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
    assertTrue(isFile(destination) && isReadable(destination));
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
    assertTrue(notExists(created) && isFile(destination) && isReadable(destination));
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
    assertTrue(isFile(link) && isReadable(link));
  }

  @Test(expected = InvalidPathException.class)
  public void testCreateLinkInvalid() throws IOException {
    Path existing = FileHelper.createFile(fileSystem.getPath(getCurrentTestName()));
    Path link = FileHelper.createLink(fileSystem.getPath("../" + getCurrentTestName() + "link"), existing);
    fail(String.format("Unexpected success in linking file %s", link.toString()));
  }

  /* Private helper */

  /**
   * Wrapper around the FileSystemProvider to test generic FS related commands.
   * All created temp directories and files used for testing are deleted upon
   * JVM exit.
   */
  private static class FileHelper {

    /**
     * Create a randomized test sandbox on each test execution
     *
     * @return the created sandbox Path
     * @throws IOException on failure to create
     */
    public static Path createTestSandbox() throws IOException {
      Path created = Files.createTempDirectory("testRoot");
      created.toFile().deleteOnExit();
      return created;
    }

    public static Path createFile(Path source) throws InvalidPathException, IOException {
      try(FileChannel fc = fileSystem.provider().newFileChannel(source,
          new TreeSet<OpenOption>(Arrays.asList(StandardOpenOption.CREATE, StandardOpenOption.WRITE)))) {
        byte [] randomBytes = new byte[1000];
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
      try(FileChannel fc = fileSystem.provider().newFileChannel(source, new TreeSet<OpenOption>(
          Arrays.asList(StandardOpenOption.READ)))) {
        byte [] readBytes = new byte[(int) source.toFile().length()];
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
      DirectoryStream<Path> dirStream = fileSystem.provider().newDirectoryStream(dir, new DirectoryStream.Filter<Path>() {
        @Override
        public boolean accept(Path entry) throws IOException { return true; }
      });
      return dirStream;
    }

    public static boolean isSameFile(Path source, Path destination) throws IOException {
      return fileSystem.provider().isSameFile(source, destination);
    }
  }
}
