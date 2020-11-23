package com.sha256Library;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
//import android.content.Context;
//import android.content.pm.PackageManager;


import com.facebook.react.ReactApplication;
import com.facebook.soloader.SoLoader;

import java.net.ConnectException;

public class MainApplication extends Application {

    private static MainApplication instance;
//    private  static MainApllication mApp;
    public static Context context;
    public static String packageName;
    public static PackageInfo packageInfo;

    public static MainApplication getInstance() {
        return instance;
    }

    @Override
    public void onCreate() {
        // TODO Auto-generated method stub
        super.onCreate();
        context = getApplicationContext();
//        instance = this;
    }






}
