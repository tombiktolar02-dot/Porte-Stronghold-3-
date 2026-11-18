package com.bolt.stronghold3wrapper;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.view.MotionEvent;
import android.view.View;

public class OverlayView extends View {
    private final Paint bgPaint = new Paint();
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint btnPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private String statusText = "Initializing SH3 Native ARM64 Bridge...";
    private float lastTouchX = -1f;
    private float lastTouchY = -1f;

    public OverlayView(Context context) {
        super(context);
        bgPaint.setColor(Color.argb(190, 12, 16, 24));
        textPaint.setColor(Color.rgb(0, 255, 160));
        textPaint.setTextSize(26f);
        textPaint.setTypeface(Typeface.MONOSPACE);

        btnPaint.setColor(Color.argb(140, 60, 120, 220));
        btnPaint.setStyle(Paint.Style.STROKE);
        btnPaint.setStrokeWidth(3f);
    }

    public void setStatusText(String text) {
        this.statusText = text;
        postInvalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();
        canvas.drawRect(24, 24, w - 24, h - 24, bgPaint);

        float y = 70f;
        for (String line : statusText.split("\n")) {
            canvas.drawText(line, 48f, y, textPaint);
            y += 36f;
        }

        if (lastTouchX >= 0 && lastTouchY >= 0) {
            canvas.drawCircle(lastTouchX, lastTouchY, 45f, btnPaint);
        }
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        lastTouchX = event.getX();
        lastTouchY = event.getY();
        invalidate();
        return true;
    }
}
