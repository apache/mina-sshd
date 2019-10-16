package org.apache.tomcat.jni;

public class Lock
{
  public static final int APR_LOCK_FCNTL = 0;
  public static final int APR_LOCK_FLOCK = 1;
  public static final int APR_LOCK_SYSVSEM = 2;
  public static final int APR_LOCK_PROC_PTHREAD = 3;
  public static final int APR_LOCK_POSIXSEM = 4;
  public static final int APR_LOCK_DEFAULT = 5;
  
  public static native long create(String paramString, int paramInt, long paramLong)
    throws Error;
  
  public static native long childInit(String paramString, long paramLong)
    throws Error;
  
  public static native int lock(long paramLong);
  
  public static native int trylock(long paramLong);
  
  public static native int unlock(long paramLong);
  
  public static native int destroy(long paramLong);
  
  public static native String lockfile(long paramLong);
  
  public static native String name(long paramLong);
  
  public static native String defname();
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Lock.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */