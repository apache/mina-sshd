package org.apache.tomcat.jni;

import java.nio.ByteBuffer;

public class Pool
{
  public static native long create(long paramLong);
  
  public static native void clear(long paramLong);
  
  public static native void destroy(long paramLong);
  
  public static native long parentGet(long paramLong);
  
  public static native boolean isAncestor(long paramLong1, long paramLong2);
  
  public static native long cleanupRegister(long paramLong, Object paramObject);
  
  public static native void cleanupKill(long paramLong1, long paramLong2);
  
  public static native void noteSubprocess(long paramLong1, long paramLong2, int paramInt);
  
  public static native ByteBuffer alloc(long paramLong, int paramInt);
  
  public static native ByteBuffer calloc(long paramLong, int paramInt);
  
  public static native int dataSet(long paramLong, String paramString, Object paramObject);
  
  public static native Object dataGet(long paramLong, String paramString);
  
  public static native void cleanupForExec();
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Pool.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */