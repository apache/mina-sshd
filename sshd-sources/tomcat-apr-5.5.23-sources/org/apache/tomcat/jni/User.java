package org.apache.tomcat.jni;

public class User
{
  public static native long uidCurrent(long paramLong)
    throws Error;
  
  public static native long gidCurrent(long paramLong)
    throws Error;
  
  public static native long uid(String paramString, long paramLong)
    throws Error;
  
  public static native long usergid(String paramString, long paramLong)
    throws Error;
  
  public static native long gid(String paramString, long paramLong)
    throws Error;
  
  public static native String username(long paramLong1, long paramLong2)
    throws Error;
  
  public static native String groupname(long paramLong1, long paramLong2)
    throws Error;
  
  public static native int uidcompare(long paramLong1, long paramLong2);
  
  public static native int gidcompare(long paramLong1, long paramLong2);
  
  public static native String homepath(String paramString, long paramLong)
    throws Error;
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\User.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */