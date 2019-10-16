package org.apache.tomcat.jni;

import java.nio.ByteBuffer;

public class File
{
  public static final int APR_FOPEN_READ = 1;
  public static final int APR_FOPEN_WRITE = 2;
  public static final int APR_FOPEN_CREATE = 4;
  public static final int APR_FOPEN_APPEND = 8;
  public static final int APR_FOPEN_TRUNCATE = 16;
  public static final int APR_FOPEN_BINARY = 32;
  public static final int APR_FOPEN_EXCL = 64;
  public static final int APR_FOPEN_BUFFERED = 128;
  public static final int APR_FOPEN_DELONCLOSE = 256;
  public static final int APR_FOPEN_XTHREAD = 512;
  public static final int APR_FOPEN_SHARELOCK = 1024;
  public static final int APR_FOPEN_NOCLEANUP = 2048;
  public static final int APR_FOPEN_SENDFILE_ENABLED = 4096;
  public static final int APR_FOPEN_LARGEFILE = 16384;
  public static final int APR_SET = 0;
  public static final int APR_CUR = 1;
  public static final int APR_END = 2;
  public static final int APR_FILE_ATTR_READONLY = 1;
  public static final int APR_FILE_ATTR_EXECUTABLE = 2;
  public static final int APR_FILE_ATTR_HIDDEN = 4;
  public static final int APR_FLOCK_SHARED = 1;
  public static final int APR_FLOCK_EXCLUSIVE = 2;
  public static final int APR_FLOCK_TYPEMASK = 15;
  public static final int APR_FLOCK_NONBLOCK = 16;
  public static final int APR_NOFILE = 0;
  public static final int APR_REG = 1;
  public static final int APR_DIR = 2;
  public static final int APR_CHR = 3;
  public static final int APR_BLK = 4;
  public static final int APR_PIPE = 5;
  public static final int APR_LNK = 6;
  public static final int APR_SOCK = 7;
  public static final int APR_UNKFILE = 127;
  public static final int APR_FPROT_USETID = 32768;
  public static final int APR_FPROT_UREAD = 1024;
  public static final int APR_FPROT_UWRITE = 512;
  public static final int APR_FPROT_UEXECUTE = 256;
  public static final int APR_FPROT_GSETID = 16384;
  public static final int APR_FPROT_GREAD = 64;
  public static final int APR_FPROT_GWRITE = 32;
  public static final int APR_FPROT_GEXECUTE = 16;
  public static final int APR_FPROT_WSTICKY = 8192;
  public static final int APR_FPROT_WREAD = 4;
  public static final int APR_FPROT_WWRITE = 2;
  public static final int APR_FPROT_WEXECUTE = 1;
  public static final int APR_FPROT_OS_DEFAULT = 4095;
  public static final int APR_FINFO_LINK = 1;
  public static final int APR_FINFO_MTIME = 16;
  public static final int APR_FINFO_CTIME = 32;
  public static final int APR_FINFO_ATIME = 64;
  public static final int APR_FINFO_SIZE = 256;
  public static final int APR_FINFO_CSIZE = 512;
  public static final int APR_FINFO_DEV = 4096;
  public static final int APR_FINFO_INODE = 8192;
  public static final int APR_FINFO_NLINK = 16384;
  public static final int APR_FINFO_TYPE = 32768;
  public static final int APR_FINFO_USER = 65536;
  public static final int APR_FINFO_GROUP = 131072;
  public static final int APR_FINFO_UPROT = 1048576;
  public static final int APR_FINFO_GPROT = 2097152;
  public static final int APR_FINFO_WPROT = 4194304;
  public static final int APR_FINFO_ICASE = 16777216;
  public static final int APR_FINFO_NAME = 33554432;
  public static final int APR_FINFO_MIN = 33136;
  public static final int APR_FINFO_IDENT = 12288;
  public static final int APR_FINFO_OWNER = 196608;
  public static final int APR_FINFO_PROT = 7340032;
  public static final int APR_FINFO_NORM = 7582064;
  public static final int APR_FINFO_DIRENT = 33554432;
  
  public static native long open(String paramString, int paramInt1, int paramInt2, long paramLong)
    throws Error;
  
  public static native int close(long paramLong);
  
  public static native int flush(long paramLong);
  
  public static native long mktemp(String paramString, int paramInt, long paramLong)
    throws Error;
  
  public static native int remove(String paramString, long paramLong);
  
  public static native int rename(String paramString1, String paramString2, long paramLong);
  
  public static native int copy(String paramString1, String paramString2, int paramInt, long paramLong);
  
  public static native int append(String paramString1, String paramString2, int paramInt, long paramLong);
  
  public static native int puts(byte[] paramArrayOfByte, long paramLong);
  
  public static native long seek(long paramLong1, int paramInt, long paramLong2)
    throws Error;
  
  public static native int putc(byte paramByte, long paramLong);
  
  public static native int ungetc(byte paramByte, long paramLong);
  
  public static native int write(long paramLong, byte[] paramArrayOfByte, int paramInt1, int paramInt2);
  
  public static native int writeb(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int writeFull(long paramLong, byte[] paramArrayOfByte, int paramInt1, int paramInt2);
  
  public static native int writeFullb(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int writev(long paramLong, byte[][] paramArrayOfByte);
  
  public static native int writevFull(long paramLong, byte[][] paramArrayOfByte);
  
  public static native int read(long paramLong, byte[] paramArrayOfByte, int paramInt1, int paramInt2);
  
  public static native int readb(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int readFull(long paramLong, byte[] paramArrayOfByte, int paramInt1, int paramInt2);
  
  public static native int readFullb(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int gets(byte[] paramArrayOfByte, int paramInt, long paramLong);
  
  public static native int getc(long paramLong)
    throws Error;
  
  public static native int eof(long paramLong);
  
  public static native String nameGet(long paramLong);
  
  public static native int permsSet(String paramString, int paramInt);
  
  public static native int attrsSet(String paramString, int paramInt1, int paramInt2, long paramLong);
  
  public static native int mtimeSet(String paramString, long paramLong1, long paramLong2);
  
  public static native int lock(long paramLong, int paramInt);
  
  public static native int unlock(long paramLong);
  
  public static native int flagsGet(long paramLong);
  
  public static native int trunc(long paramLong1, long paramLong2);
  
  public static native int pipeCreate(long[] paramArrayOfLong, long paramLong);
  
  public static native long pipeTimeoutGet(long paramLong)
    throws Error;
  
  public static native int pipeTimeoutSet(long paramLong1, long paramLong2);
  
  public static native long dup(long paramLong1, long paramLong2, long paramLong3)
    throws Error;
  
  public static native int dup2(long paramLong1, long paramLong2, long paramLong3);
  
  public static native int stat(FileInfo paramFileInfo, String paramString, int paramInt, long paramLong);
  
  public static native int infoGet(FileInfo paramFileInfo, int paramInt, long paramLong);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\File.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */