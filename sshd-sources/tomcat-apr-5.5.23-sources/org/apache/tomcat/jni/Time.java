/*    */ package org.apache.tomcat.jni;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class Time
/*    */ {
/*    */   public static final long APR_USEC_PER_SEC = 1000000L;
/*    */   
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   public static final long APR_MSEC_PER_USEC = 1000L;
/*    */   
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   public static long sec(long t)
/*    */   {
/* 36 */     return t / 1000000L;
/*    */   }
/*    */   
/*    */ 
/*    */   public static long msec(long t)
/*    */   {
/* 42 */     return t / 1000L;
/*    */   }
/*    */   
/*    */   public static native long now();
/*    */   
/*    */   public static native String rfc822(long paramLong);
/*    */   
/*    */   public static native String ctime(long paramLong);
/*    */   
/*    */   public static native void sleep(long paramLong);
/*    */ }


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Time.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */