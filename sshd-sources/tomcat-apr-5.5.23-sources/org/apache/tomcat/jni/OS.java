/*    */ package org.apache.tomcat.jni;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class OS
/*    */ {
/*    */   private static final int UNIX = 1;
/*    */   
/*    */ 
/*    */ 
/*    */   private static final int NETWARE = 2;
/*    */   
/*    */ 
/*    */ 
/*    */   private static final int WIN32 = 3;
/*    */   
/*    */ 
/*    */ 
/*    */   private static final int WIN64 = 4;
/*    */   
/*    */ 
/*    */   private static final int LINUX = 5;
/*    */   
/*    */ 
/*    */   private static final int SOLARIS = 6;
/*    */   
/*    */ 
/*    */   private static final int BSD = 7;
/*    */   
/*    */ 
/*    */   public static final int LOG_EMERG = 1;
/*    */   
/*    */ 
/*    */   public static final int LOG_ERROR = 2;
/*    */   
/*    */ 
/*    */   public static final int LOG_NOTICE = 3;
/*    */   
/*    */ 
/*    */   public static final int LOG_WARN = 4;
/*    */   
/*    */ 
/*    */   public static final int LOG_INFO = 5;
/*    */   
/*    */ 
/*    */   public static final int LOG_DEBUG = 6;
/*    */   
/*    */ 
/* 50 */   public static final boolean IS_UNIX = is(1);
/* 51 */   public static final boolean IS_NETWARE = is(2);
/* 52 */   public static final boolean IS_WIN32 = is(3);
/* 53 */   public static final boolean IS_WIN64 = is(4);
/* 54 */   public static final boolean IS_LINUX = is(5);
/* 55 */   public static final boolean IS_SOLARIS = is(6);
/* 56 */   public static final boolean IS_BSD = is(7);
/*    */   
/*    */   private static native boolean is(int paramInt);
/*    */   
/*    */   public static native String defaultEncoding(long paramLong);
/*    */   
/*    */   public static native String localeEncoding(long paramLong);
/*    */   
/*    */   public static native int random(byte[] paramArrayOfByte, int paramInt);
/*    */   
/*    */   public static native int info(long[] paramArrayOfLong);
/*    */   
/*    */   public static native String expand(String paramString);
/*    */   
/*    */   public static native void sysloginit(String paramString);
/*    */   
/*    */   public static native void syslog(int paramInt, String paramString);
/*    */ }


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\OS.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */