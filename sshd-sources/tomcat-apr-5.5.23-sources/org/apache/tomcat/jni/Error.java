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
/*    */ public class Error
/*    */   extends Exception
/*    */ {
/*    */   private int error;
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
/*    */   private String description;
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
/*    */   private Error(int error, String description)
/*    */   {
/* 46 */     super(description);
/* 47 */     this.error = error;
/* 48 */     this.description = description;
/*    */   }
/*    */   
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   public int getError()
/*    */   {
/* 58 */     return this.error;
/*    */   }
/*    */   
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   public String getDescription()
/*    */   {
/* 68 */     return this.description;
/*    */   }
/*    */   
/*    */   public static native int osError();
/*    */   
/*    */   public static native int netosError();
/*    */   
/*    */   public static native String strerror(int paramInt);
/*    */ }


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Error.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */