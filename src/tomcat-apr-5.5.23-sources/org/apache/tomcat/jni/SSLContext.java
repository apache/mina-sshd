package org.apache.tomcat.jni;

public final class SSLContext
{
  public static native long make(long paramLong, int paramInt1, int paramInt2)
    throws Exception;
  
  public static native int free(long paramLong);
  
  public static native void setContextId(long paramLong, String paramString);
  
  public static native void setBIO(long paramLong1, long paramLong2, int paramInt);
  
  public static native void setOptions(long paramLong, int paramInt);
  
  public static native void setQuietShutdown(long paramLong, boolean paramBoolean);
  
  public static native boolean setCipherSuite(long paramLong, String paramString)
    throws Exception;
  
  public static native boolean setCARevocation(long paramLong, String paramString1, String paramString2)
    throws Exception;
  
  public static native boolean setCertificateChainFile(long paramLong, String paramString, boolean paramBoolean);
  
  public static native boolean setCertificate(long paramLong, String paramString1, String paramString2, String paramString3, int paramInt)
    throws Exception;
  
  public static native boolean setCACertificate(long paramLong, String paramString1, String paramString2)
    throws Exception;
  
  public static native void setShutdowType(long paramLong, int paramInt);
  
  public static native void setVerify(long paramLong, int paramInt1, int paramInt2);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\SSLContext.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */