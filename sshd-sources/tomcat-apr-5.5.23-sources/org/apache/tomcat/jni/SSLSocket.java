package org.apache.tomcat.jni;

public class SSLSocket
{
  public static native int attach(long paramLong1, long paramLong2)
    throws Exception;
  
  public static native int handshake(long paramLong);
  
  public static native int renegotiate(long paramLong);
  
  public static native byte[] getInfoB(long paramLong, int paramInt)
    throws Exception;
  
  public static native String getInfoS(long paramLong, int paramInt)
    throws Exception;
  
  public static native int getInfoI(long paramLong, int paramInt)
    throws Exception;
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\SSLSocket.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */