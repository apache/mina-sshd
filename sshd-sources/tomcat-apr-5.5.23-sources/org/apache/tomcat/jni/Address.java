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
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class Address
/*    */ {
/* 28 */   public static String APR_ANYADDR = "0.0.0.0";
/*    */   
/*    */   public static native boolean fill(Sockaddr paramSockaddr, long paramLong);
/*    */   
/*    */   public static native Sockaddr getInfo(long paramLong);
/*    */   
/*    */   public static native long info(String paramString, int paramInt1, int paramInt2, int paramInt3, long paramLong)
/*    */     throws Exception;
/*    */   
/*    */   public static native String getnameinfo(long paramLong, int paramInt);
/*    */   
/*    */   public static native String getip(long paramLong);
/*    */   
/*    */   public static native int getservbyname(long paramLong, String paramString);
/*    */   
/*    */   public static native long get(int paramInt, long paramLong)
/*    */     throws Exception;
/*    */   
/*    */   public static native boolean equal(long paramLong1, long paramLong2);
/*    */ }


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Address.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */