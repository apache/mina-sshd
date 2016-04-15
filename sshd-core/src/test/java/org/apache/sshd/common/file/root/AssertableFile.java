package org.apache.sshd.common.file.root;

import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.util.test.BaseTestSupport;


/**
 * TODO upgrade to default methods in JDK 8
 */
public class AssertableFile extends BaseTestSupport {

  public AssertableFile() {
    super();
  }

  public static Boolean notExists(Path p) {
    Boolean cond = !Files.exists(p);
    assertTrue(p + " does not exist", cond);
    return cond;
  }

  public static Boolean isFile(Path p) {
    Boolean cond = Files.exists(p);
    assertTrue(p + " exists", cond);
    return cond;
  }

  public static Boolean isDir(Path p) {
    Boolean cond = Files.isDirectory(p);
    assertTrue(p + " is directory", cond);
    return cond;
  }

  public static Boolean isReadable(Path p) {
    Boolean cond = Files.isReadable(p);
    assertTrue(p + " is readable by user", cond);
    return cond;
  }

  public static Boolean isNonEmpty(byte[] bytes) {
    Boolean cond = !NumberUtils.isEmpty(bytes);
    assertTrue("bytes are non empty", cond);
    return cond;
  }

  public static boolean isRootedAt(Path root, Path check) {
    boolean cond = check.toAbsolutePath().normalize()
        .startsWith(root.toAbsolutePath().normalize());
    assertTrue(check + " is subpath of parent " + root, cond);
    return cond;
  }
}

