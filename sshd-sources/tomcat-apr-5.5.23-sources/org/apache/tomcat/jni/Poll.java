package org.apache.tomcat.jni;

public class Poll
{
  public static final int APR_POLLIN = 1;
  public static final int APR_POLLPRI = 2;
  public static final int APR_POLLOUT = 4;
  public static final int APR_POLLERR = 16;
  public static final int APR_POLLHUP = 32;
  public static final int APR_POLLNVAL = 64;
  public static final int APR_POLLSET_THREADSAFE = 1;
  public static final int APR_NO_DESC = 0;
  public static final int APR_POLL_SOCKET = 1;
  public static final int APR_POLL_FILE = 2;
  public static final int APR_POLL_LASTDESC = 3;
  
  public static native long create(int paramInt1, long paramLong1, int paramInt2, long paramLong2)
    throws Error;
  
  public static native int destroy(long paramLong);
  
  public static native int add(long paramLong1, long paramLong2, int paramInt);
  
  public static native int remove(long paramLong1, long paramLong2);
  
  public static native int poll(long paramLong1, long paramLong2, long[] paramArrayOfLong, boolean paramBoolean);
  
  public static native int maintain(long paramLong, long[] paramArrayOfLong, boolean paramBoolean);
  
  public static native void setTtl(long paramLong1, long paramLong2);
  
  public static native long getTtl(long paramLong);
  
  public static native int pollset(long paramLong, long[] paramArrayOfLong);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Poll.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */