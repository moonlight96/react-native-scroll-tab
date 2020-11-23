package com.sha256Library;

import android.app.Activity;
import android.os.Bundle;
import android.support.annotation.Nullable;

import com.sha256lib.R;

public class MainActivityApplication extends Activity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        MainApplication mainApllication = (MainApplication) getApplication();

    }
}
