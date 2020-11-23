package com.sha256Library;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;


import android.content.Context;
import android.content.pm.PackageItemInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.text.TextUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.File;
import java.io.FileInputStream;

import java.math.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class Sha256Module extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;


  public Sha256Module(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "sha256Lib";
  }

  String buildHash(final String toHash, final String algo, final Integer length) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    MessageDigest md = MessageDigest.getInstance(algo);
    md.update(toHash.getBytes("UTF-8"));
    byte[] digest = md.digest();
    return String.format("%0" + length.toString() + "x", new java.math.BigInteger(1, digest));
  }


  @ReactMethod
  public void sha256(final String toHash, Promise promise) {
      try {
          String hash = buildHash(toHash, "SHA-256", 64);
          promise.resolve(hash);
      } catch (NoSuchAlgorithmException e) {
          e.printStackTrace();
          promise.reject("sha256", e.getMessage());
      } catch (UnsupportedEncodingException e) {
          e.printStackTrace();
          promise.reject("sha256", e.getMessage());
      }
  }

  @ReactMethod
  public void sha1(final String toHash, Promise promise) {
      try {
          String hash = buildHash(toHash, "SHA-1", 40);
          promise.resolve(hash);
      } catch (NoSuchAlgorithmException e) {
          e.printStackTrace();
          promise.reject("sha1", e.getMessage());
      } catch (UnsupportedEncodingException e) {
          e.printStackTrace();
          promise.reject("sha1", e.getMessage());
      }
  }

    /**

     * 获取文件MD5值

     *

     * @param file

     * @return

     */
    @ReactMethod
    public static String getFileMD5(File file)

    {

        if (!file.isFile())

        {

            return null;

        }

        MessageDigest digest;

        FileInputStream in;

        byte buffer[] = new byte[1024];

        int len;

        try

        {

            digest = MessageDigest.getInstance("MD5");

            in = new FileInputStream(file);

            while ((len = in.read(buffer, 0, 1024)) != -1)

            {

                digest.update(buffer, 0, len);

            }

            in.close();

        }

        catch (Exception e)

        {

            e.printStackTrace();

            return null;

        }

        return bytesToHexString(digest.digest());

    }



    public static String bytesToHexString(byte[] src)

    {

        StringBuilder stringBuilder = new StringBuilder("");

        if (src == null || src.length <= 0)

        {

            return null;

        }

        for (byte aSrc : src)

        {

            int v = aSrc & 0xFF;

            String hv = Integer.toHexString(v);

            if (hv.length() < 2)

            {

                stringBuilder.append(0);

            }

            stringBuilder.append(hv);

        }

        return stringBuilder.toString();

    }

@ReactMethod
    private String apkShaCheck() {
        MessageDigest msgDigest = null;
        try {
            msgDigest = MessageDigest.getInstance("SHA-1");
            byte[] bytes = new byte[1024];
            int byteCount;

            MainApplication mainApllication = MainApplication.getInstance();
            mainApllication.onCreate();
            Context context = mainApllication.getApplicationContext();
            String apkPath = context.getPackageCodePath();

//            String apkPath =  new Application().getPackageCodePath();
//            Log.i(TAG, "apkPath = " + apkPath);
            FileInputStream fis = new FileInputStream(new File(apkPath));
            while ((byteCount = fis.read(bytes)) > 0) {
                msgDigest.update(bytes, 0, byteCount);
            }
            BigInteger bi = new BigInteger(1, msgDigest.digest());
            String sha = bi.toString(16);
//            Log.i(TAG, "apk sha = " + sha);
            fis.close();
     return sha;
            // 这里添加从服务器中获取哈希值然后进行对比校验
        } catch (Exception e) {
            e.printStackTrace();
        }
        return  null;
    }

    /**
     * MD5加密
     * @param byteStr 需要加密的内容
     * @return 返回 byteStr的md5值
     */
    @ReactMethod
    public static String encryptionMD5(byte[] byteStr) {
        MessageDigest messageDigest = null;
        StringBuffer md5StrBuff = new StringBuffer();
        try {
            messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.reset();
            messageDigest.update(byteStr);
            byte[] byteArray = messageDigest.digest();
//            return Base64.encodeToString(byteArray,Base64.NO_WRAP);
            for (int i = 0; i < byteArray.length; i++) {
                if (Integer.toHexString(0xFF & byteArray[i]).length() == 1) {
                    md5StrBuff.append("0").append(Integer.toHexString(0xFF & byteArray[i]));
                } else {
                    md5StrBuff.append(Integer.toHexString(0xFF & byteArray[i]));
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return md5StrBuff.toString();
    }

//    public String getT(Context context){
//        try{
//            PackageManager packageManager = context.getPackageManager();
//            packageManager.getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNATURES);
//        }catch (Exception e){
//            e.printStackTrace();
//        }
//
//
//    }

    /**
     * 获取app签名md5值,与“keytool -list -keystore D:\Desktop\app_key”‘keytool -printcert     *file D:\Desktop\CERT.RSA’获取的md5值一样
     */
   @ReactMethod
   public String getSignMd5Str() {
        System.out.println("88889");
//       SignCheckUtil signCheckUtil = new SignCheckUtil(MainApllication.context,"MD5");
//       return signCheckUtil.getCertificateSHA1Fingerprint();
       try {
           MainApplication mainApllication =MainApplication.getInstance();
           mainApllication.onCreate();
//           Context context = mainApllication.getApplicationContext();
           Context context = mainApllication;

//           PackageManager packageManager = MainApllication.context;
           String packageName=  MainApplication.packageName;


           PackageInfo packageInfo = MainApplication.packageInfo;


           Signature[] signs = packageInfo.signatures;
           Signature sign = signs[0];
           String signStr = encryptionMD5(sign.toByteArray());

           return signStr;
       } catch (Exception e) {
           e.printStackTrace();
       }
       return "";
   }

   @ReactMethod
   public String getTes(){
       SignCheckUtil signCheckUtil = new SignCheckUtil(MainApplication.context,"MD5");
       return signCheckUtil.getCertificateSHA1Fingerprint();
   }

}

class SignCheckUtil {

    private Context context;
    private String cer = null;
    private String type = "SHA1";
    private String sha1RealCer = "签名SHA1值";
    private String md5RealCer = "签名MD5";
    private static final String TAG = "sign";

    public SignCheckUtil(Context context,String type) {
        this.context = context;
        this.type = type;
    }



    /**
     * 获取应用的签名
//     *
//     * @return
     */
    public  String getCertificateSHA1Fingerprint() {
        String hexString = "";


        //获取包管理器
        PackageManager pm = context.getPackageManager();

        //获取当前要获取 SHA1 值的包名，也可以用其他的包名，但需要注意，
        //在用其他包名的前提是，此方法传递的参数 Context 应该是对应包的上下文。
        String packageName = context.getPackageName();

        //签名信息
        Signature[] signatures = null;

        try {
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.P) {
                PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo signingInfo = packageInfo.signingInfo;
                signatures = signingInfo.getApkContentsSigners();
            } else {
                //获得包的所有内容信息类
                PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                signatures = packageInfo.signatures;
            }


//        Signature[] signatures = packageInfo.signatures;
            byte[] cert = signatures[0].toByteArray();

            //将签名转换为字节数组流
            InputStream input = new ByteArrayInputStream(cert);

            //证书工厂类，这个类实现了出厂合格证算法的功能
            CertificateFactory cf = CertificateFactory.getInstance("X509");

            //X509 证书，X.509 是一种非常通用的证书格式
            X509Certificate c = null;
            c = (X509Certificate) cf.generateCertificate(input);


            //加密算法的类，这里的参数可以使 MD4,MD5 等加密算法
            MessageDigest md = MessageDigest.getInstance(type);

            //获得公钥
            byte[] publicKey = md.digest(c.getEncoded());

            //字节到十六进制的格式转换
            hexString = byte2HexFormatted(publicKey);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hexString.trim();
    }

    //这里是将获取到得编码进行16 进制转换
    private String byte2HexFormatted(byte[] arr) {

        StringBuilder str = new StringBuilder(arr.length * 2);

        for (int i = 0; i < arr.length; i++) {
            String h = Integer.toHexString(arr[i]);
            int l = h.length();
            if (l == 1)
                h = "0" + h;
            if (l > 2)
                h = h.substring(l - 2, l);
            str.append(h.toUpperCase());
            if (i < (arr.length - 1))
                str.append(':');
        }
        return str.toString();
    }

    /**
     * 检测签名是否正确
     *
     * @return true 签名正常 false 签名不正常
     */
    public boolean check() {

        if (this.sha1RealCer != null || md5RealCer!= null) {
            cer = getCertificateSHA1Fingerprint();
//            Log.d(TAG, "check: " + cer);
            if ((TextUtils.equals(type,"SHA1") && this.cer.equals(this.sha1RealCer)) || (TextUtils.equals(type,"MD5") && this.cer.equals(this.md5RealCer))) {
                return true;
            }
        }
        return false;
    }
}
