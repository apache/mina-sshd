package org.apache.tomcat.jni;

public class Procattr
{
  public static native long create(long paramLong)
    throws Error;
  
  public static native int ioSet(long paramLong, int paramInt1, int paramInt2, int paramInt3);
  
  public static native int childInSet(long paramLong1, long paramLong2, long paramLong3);
  
  public static native int childOutSet(long paramLong1, long paramLong2, long paramLong3);
  
  public static native int childErrSet(long paramLong1, long paramLong2, long paramLong3);
  
  public static native int dirSet(long paramLong, String paramString);
  
  public static native int cmdtypeSet(long paramLong, int paramInt);
  
  public static native int detachSet(long paramLong, int paramInt);
  
  public static native int errorCheckSet(long paramLong, int paramInt);
  
  public static native int addrspaceSet(long paramLong, int paramInt);
  
  public static native void errfnSet(long paramLong1, long paramLong2, Object paramObject);
  
  public static native int userSet(long paramLong, String paramString1, String paramString2);
  
  public static native int groupSet(long paramLong, String paramString);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Procattr.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */