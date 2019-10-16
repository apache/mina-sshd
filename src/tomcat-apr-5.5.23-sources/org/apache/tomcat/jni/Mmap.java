package org.apache.tomcat.jni;

public class Mmap
{
  public static final int APR_MMAP_READ = 1;
  public static final int APR_MMAP_WRITE = 2;
  
  public static native long create(long paramLong1, long paramLong2, long paramLong3, int paramInt, long paramLong4)
    throws Error;
  
  public static native long dup(long paramLong1, long paramLong2)
    throws Error;
  
  public static native int delete(long paramLong);
  
  public static native long offset(long paramLong1, long paramLong2)
    throws Error;
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Mmap.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */