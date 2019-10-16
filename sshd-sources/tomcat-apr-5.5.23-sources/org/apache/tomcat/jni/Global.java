package org.apache.tomcat.jni;

public class Global
{
  public static native long create(String paramString, int paramInt, long paramLong)
    throws Error;
  
  public static native long childInit(String paramString, long paramLong)
    throws Error;
  
  public static native int lock(long paramLong);
  
  public static native int trylock(long paramLong);
  
  public static native int unlock(long paramLong);
  
  public static native int destroy(long paramLong);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Global.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */