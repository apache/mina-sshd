package org.apache.tomcat.jni;

public class Directory
{
  public static native int make(String paramString, int paramInt, long paramLong);
  
  public static native int makeRecursive(String paramString, int paramInt, long paramLong);
  
  public static native int remove(String paramString, long paramLong);
  
  public static native String tempGet(long paramLong);
  
  public static native long open(String paramString, long paramLong)
    throws Error;
  
  public static native int close(long paramLong);
  
  public static native int rewind(long paramLong);
  
  public static native int read(FileInfo paramFileInfo, int paramInt, long paramLong);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Directory.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */