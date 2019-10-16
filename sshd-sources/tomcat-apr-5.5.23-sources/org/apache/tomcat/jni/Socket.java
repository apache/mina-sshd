package org.apache.tomcat.jni;

import java.nio.ByteBuffer;

public class Socket
{
  public static final int SOCK_STREAM = 0;
  public static final int SOCK_DGRAM = 1;
  public static final int APR_SO_LINGER = 1;
  public static final int APR_SO_KEEPALIVE = 2;
  public static final int APR_SO_DEBUG = 4;
  public static final int APR_SO_NONBLOCK = 8;
  public static final int APR_SO_REUSEADDR = 16;
  public static final int APR_SO_SNDBUF = 64;
  public static final int APR_SO_RCVBUF = 128;
  public static final int APR_SO_DISCONNECTED = 256;
  public static final int APR_TCP_NODELAY = 512;
  public static final int APR_TCP_NOPUSH = 1024;
  public static final int APR_RESET_NODELAY = 2048;
  public static final int APR_INCOMPLETE_READ = 4096;
  public static final int APR_INCOMPLETE_WRITE = 8192;
  public static final int APR_IPV6_V6ONLY = 16384;
  public static final int APR_TCP_DEFER_ACCEPT = 32768;
  public static final int APR_SHUTDOWN_READ = 0;
  public static final int APR_SHUTDOWN_WRITE = 1;
  public static final int APR_SHUTDOWN_READWRITE = 2;
  public static final int APR_IPV4_ADDR_OK = 1;
  public static final int APR_IPV6_ADDR_OK = 2;
  public static final int APR_UNSPEC = 0;
  public static final int APR_INET = 1;
  public static final int APR_INET6 = 2;
  public static final int APR_PROTO_TCP = 6;
  public static final int APR_PROTO_UDP = 17;
  public static final int APR_PROTO_SCTP = 132;
  public static final int APR_LOCAL = 0;
  public static final int APR_REMOTE = 1;
  public static final int SOCKET_GET_POOL = 0;
  public static final int SOCKET_GET_IMPL = 1;
  public static final int SOCKET_GET_APRS = 2;
  public static final int SOCKET_GET_TYPE = 3;
  
  public static native long create(int paramInt1, int paramInt2, int paramInt3, long paramLong)
    throws Exception;
  
  public static native int shutdown(long paramLong, int paramInt);
  
  public static native int close(long paramLong);
  
  public static native void destroy(long paramLong);
  
  public static native int bind(long paramLong1, long paramLong2);
  
  public static native int listen(long paramLong, int paramInt);
  
  public static native long accept(long paramLong)
    throws Exception;
  
  public static native int acceptfilter(long paramLong, String paramString1, String paramString2);
  
  public static native boolean atmark(long paramLong);
  
  public static native int connect(long paramLong1, long paramLong2);
  
  public static native int send(long paramLong, byte[] paramArrayOfByte, int paramInt1, int paramInt2);
  
  public static native int sendb(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int sendbb(long paramLong, int paramInt1, int paramInt2);
  
  public static native int sendv(long paramLong, byte[][] paramArrayOfByte);
  
  public static native int sendto(long paramLong1, long paramLong2, int paramInt1, byte[] paramArrayOfByte, int paramInt2, int paramInt3);
  
  public static native int recv(long paramLong, byte[] paramArrayOfByte, int paramInt1, int paramInt2);
  
  public static native int recvt(long paramLong1, byte[] paramArrayOfByte, int paramInt1, int paramInt2, long paramLong2);
  
  public static native int recvb(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int recvbb(long paramLong, int paramInt1, int paramInt2);
  
  public static native int recvbt(long paramLong1, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2, long paramLong2);
  
  public static native int recvbbt(long paramLong1, int paramInt1, int paramInt2, long paramLong2);
  
  public static native int recvFrom(long paramLong1, long paramLong2, int paramInt1, byte[] paramArrayOfByte, int paramInt2, int paramInt3);
  
  public static native int optSet(long paramLong, int paramInt1, int paramInt2);
  
  public static native int optGet(long paramLong, int paramInt)
    throws Exception;
  
  public static native int timeoutSet(long paramLong1, long paramLong2);
  
  public static native long timeoutGet(long paramLong)
    throws Exception;
  
  public static native long sendfile(long paramLong1, long paramLong2, byte[][] paramArrayOfByte1, byte[][] paramArrayOfByte2, long paramLong3, long paramLong4, int paramInt);
  
  public static native long sendfilen(long paramLong1, long paramLong2, long paramLong3, long paramLong4, int paramInt);
  
  public static native long pool(long paramLong)
    throws Exception;
  
  private static native long get(long paramLong, int paramInt);
  
  public static native void setsbb(long paramLong, ByteBuffer paramByteBuffer);
  
  public static native void setrbb(long paramLong, ByteBuffer paramByteBuffer);
  
  public static native int dataSet(long paramLong, String paramString, Object paramObject);
  
  public static native Object dataGet(long paramLong, String paramString);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Socket.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */