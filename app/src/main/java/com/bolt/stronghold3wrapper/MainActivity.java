package com.bolt.stronghold3wrapper;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.SurfaceView;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;

public class MainActivity extends Activity {
    static {
        System.loadLibrary("pe_arm64_bridge");
    }

    private static final String GAME_BIN_DIR =
            "/sdcard/Download/gamedata/Stronghold3/bin/win32_release";

    private OverlayView overlayView;

    public native String inspectEngineBinaries(String binDir);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(
                WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN
        );

        FrameLayout root = new FrameLayout(this);
        SurfaceView surfaceView = new SurfaceView(this);
        overlayView = new OverlayView(this);

        root.addView(surfaceView);
        root.addView(overlayView);
        setContentView(root);

        checkStorageAndRunInspection();
    }

    @Override
    protected void onResume() {
        super.onResume();
        runNativeInspectionAsync();
    }

    private void checkStorageAndRunInspection() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            overlayView.setStatusText("Grant 'All Files Access' permission to read Stronghold 3 binaries...");
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } catch (Exception e) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                startActivity(intent);
            }
        } else {
            runNativeInspectionAsync();
        }
    }

    private void runNativeInspectionAsync() {
        new Thread(() -> {
            final String report = inspectEngineBinaries(GAME_BIN_DIR);
            runOnUiThread(() -> overlayView.setStatusText(report));
        }).start();
    }
}
