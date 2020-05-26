package org.apache.tomcat.jni;

public class Local
{
  public static native long create(String paramString, long paramLong)
    throws Exception;
  
  public static native int bind(long paramLong1, long paramLong2);
  
  public static native int listen(long paramLong, int paramInt);
  
  public static native long accept(long paramLong)
    throws Exception;
  
  public static native int connect(long paramLong1, long paramLong2);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Local.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */