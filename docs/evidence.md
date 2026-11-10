# 证据摘录

本文件只摘与漏洞直接相关的反编译与清单内容，逐条标注来源文件，方便复核。样本 `SystemHelper_3.0.0-20231222.apk`，包名 `com.mobiletools.systemhelper`，versionCode 31，targetSdk 33。

## 一 清单未对服务设权限

来源 `apktool/AndroidManifest.xml`

```xml
<permission android:name="com.mobiletools.systemhelper.permission" android:protectionLevel="signature"/>
...
<service android:enabled="true" android:name="com.baidu.location.f" android:process=":remote"/>
<service android:exported="true" android:name="com.mobiletools.systemhelper.service.RegisterHelperService">
    <intent-filter>
        <action android:name="com.mobiletools.systemhelper.service.IRegisterHelperService"/>
    </intent-filter>
</service>
<service android:name="com.mobiletools.systemhelper.service.RegisterIntentService"/>
<service android:name="com.mobiletools.systemhelper.service.RegisterJobService" android:permission="android.permission.BIND_JOB_SERVICE"/>
```

同一份清单里自定义了 `com.mobiletools.systemhelper.permission`（`protectionLevel="signature"`），但**这个权限没被任何组件引用**，`RegisterHelperService` 也没有 `android:permission`。紧邻的 `RegisterJobService` 却写了 `BIND_JOB_SERVICE`，因此这是遗漏而非有意开放。

## 二 onTransact 的五个事务码

来源 `apktool/smali/com/mobiletools/systemhelper/service/a$a.smali`，接口 `com.mobiletools.systemhelper.service.a`（AIDL 声明名 `IRegisterHelperService`）。

```smali
if-eq p1, v0, :cond_6      # v0 = 1
const/4 v2, 0x2
if-eq p1, v2, :cond_5      # 2
const/4 v2, 0x3
if-eq p1, v2, :cond_4      # 3
const/4 v2, 0x4
if-eq p1, v2, :cond_2      # 4
const/4 v2, 0x5
if-eq p1, v2, :cond_1      # 5
```

各分支参数读取方式：

```smali
:cond_6                    # code 1
    invoke-virtual {p2, v1}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;
    move-result-object p1
    invoke-interface {p0, p1}, Lcom/mobiletools/systemhelper/service/a;->a(Ljava/lang/String;)V

:cond_5                    # code 2
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I
    invoke-interface {p0, p1}, Lcom/mobiletools/systemhelper/service/a;->a(I)V

:cond_4                    # code 3
    invoke-interface {p0}, Lcom/mobiletools/systemhelper/service/a;->b()V

:cond_2                    # code 4
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I
    ...                         # 非 0 转 true
    invoke-interface {p0, p1}, Lcom/mobiletools/systemhelper/service/a;->a(Z)V

:cond_1                    # code 5
    invoke-interface {p0}, Lcom/mobiletools/systemhelper/service/a;->a()Z
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V
    invoke-virtual {p3, p0}, Landroid/os/Parcel;->writeInt(I)V
```

`enforceInterface` 只校验 Parcel 里的 descriptor 字符串等于 `com.mobiletools.systemhelper.service.IRegisterHelperService`。这个字符串是公开的，写在接口定义里，不构成任何调用方鉴权。

## 三 serverAddress 的写入与消费

来源 `jadx/sources/com/mobiletools/systemhelper/service/RegisterHelperService.java`

```java
public void a(String str) { m.a(RegisterHelperService.this.f1420b, str); }
```

来源 `jadx/sources/c/d/a/b/m.java`

```java
public static void a(Context context, String str) {
    b(context, "serverAddress", str);
}

public static void b(Context context, String str, String str2) {
    SharedPreferences.Editor editorEdit = context.getSharedPreferences(
            "com_mobiletools_systemhelper_preference", 4).edit();
    editorEdit.putString(str, str2);
    editorEdit.commit();
}

public static String d(Context context) {
    return e.f1333b ? e.l : a(context, "serverAddress", e.l);
}
```

`4` 是 `MODE_MULTI_PROCESS`，写入后同应用其他进程也立即读到。`e.l` 是默认值 `http://dm.wo.com.cn:18080/register`，`e.f1333b` 在 `c/d/a/b/e.java` 里定义为 `public static boolean f1333b = false` 且**全工程无赋值点**，所以覆盖值永远生效。

来源 `jadx/sources/com/mobiletools/systemhelper/control/f.java`

```java
String str = m.d(this.f1418b) + "?ver=5.0&model=" + URLEncoder.encode(bVar.f1411b, "utf-8")
        + "&manuf=" + URLEncoder.encode(bVar.f1410a, "utf-8") + "&sign=" + strEncode;
byte[] bArrA2 = c.d.a.b.c.a(strA, bArrA);
g gVar = new g();
boolean zA = gVar.a(str, bArrA2, bArrA);
```

上报线程每次构造 URL 时都调 `m.d()`，所以事务码 1 改完，下一次上报就发往新地址，不必重启目标进程。

## 四 门控条件，决定 PoC 何时看得到真实 POST

来源 `jadx/sources/com/mobiletools/systemhelper/control/f.java`

```java
private synchronized boolean b(b bVar) {
    if (a(bVar.g) && a(bVar.s)) {                     // 两个 IMEI 都必须是 15 位纯数字
        if (m.f(this.f1418b).booleanValue()) {        // 有网络
            if ((m.g(...).booleanValue() && m.a(bVar).booleanValue())
                    || (!l.c(...).booleanValue() && m.b(bVar).booleanValue())) {
                if (a(bVar)) { new d(this.f1418b).start(); return true; }
            }
        }
        ...saveToDb(v);                               // 不满足就只落本地库
        return false;
    }
    return false;
}
```

来源 `jadx/sources/c/d/a/b/m.java`

```java
public static Boolean g(Context context) {   // WiFi 是否 CONNECTED
    return Boolean.valueOf(((ConnectivityManager) context.getSystemService("connectivity"))
            .getNetworkInfo(1).getState() == NetworkInfo.State.CONNECTED);
}

public static Boolean a(com.mobiletools.systemhelper.control.b bVar) {   // 是否中国网
    if (bVar.k.trim().startsWith("460") || bVar.w.trim().startsWith("460")) { return Boolean.valueOf(true); }
    ...
}

public static Boolean b(b bVar) {   // 是否联通数据卡
    ... bVar.k 等于 46001/46006/46009
        或 bVar.h 以 898601/898606/898609 开头 ...
}
```

`b` 的字段映射（`control/b.java` 的 `a()`）：`h` = ICCID1、`k` = MNC1、`t` = ICCID2、`w` = MNC2、`E` = DataSlot。

关键点是 `m.a()` 的条件是 `startsWith("460")`，覆盖全部中国大陆运营商，不是联通专属。而 `l.c(ctx)` 恒 false（见下），所以 `(!l.c && m.b)` 退化成 `m.b`，两条路径是「或」的关系。

### 需要更正原报告的一处推断

原报告 §10 写「本机是中国电信卡，按上述逻辑 `isUnicomNetwork=false`，因此上报会一直落库不外发」，并把 `!l.c(ctx)` 视为「恒真但不起作用」。这个结论不成立：

- 若 `!l.c(ctx)` 恒真且不起作用，那么第二项 `m.b(bVar)` 就是唯一判据，此时电信卡确实不外发
- 但第一项 `m.g() && m.a()` 是独立分支，WiFi 已连且 MNC 以 460 开头时直接为真，与联通判定无关

也就是说电信卡 + WiFi 的机器会走第一条分支真正 POST。原报告把 `A || (!B && C)` 读成了「必须 C」。这条更正把受影响面从联通用户扩大到「插任意中国大陆运营商卡且连 WiFi」的绝大多数预装设备。

### `l.c(ctx)` 为什么恒 false

来源 `jadx/sources/c/d/a/a/a.java`

```java
@Override // c.d.a.a.l.c
public boolean a(Context context) {
    return new ServiceState().getRoaming();
}
```

每次调用都 `new` 一个空的 `ServiceState`，从不装载真实业务状态，`getRoaming()` 恒为 false。`aosp` 的 `ServiceState` 默认构造把 `mRoaming` 初始化为 `false`，只有在 `copyFrom` 或 Parcel 反序列化时才可能为真。所以 `!l.c(ctx)` 恒真，这一项在布尔式里不起过滤作用，原报告这半句是对的，但由此推出的「因此不外发」是错的。

## 五 广播入口可被用来立即触发

来源 `jadx/sources/com/mobiletools/systemhelper/control/OnBootReceiver.java`

```java
public void onReceive(Context context, Intent intent) {
    f1401a = context;
    if (!c.d.a.b.e.f1333b) {
        c.d.a.b.e.f1332a = m.a(context, "preference_enable_log", (Boolean) false).booleanValue();
    }
    i.a("OnBootReceiver", "onReceive-->intent action: " + intent.getAction());
    c.d.a.a.a.e(context);
    String action = intent.getAction();
    if (action != null && (action.equals("android.intent.action.BOOT_COMPLETED")
            || action.equals("android.intent.action.QUICKBOOT_POWERON"))) {
        ...排 4 分钟与 24h/6h 闹钟...
        return;
    }
    i.a("OnBootReceiver", "SIM_STATE_CHANGED, state:" + ...);
    new SIMStateReceiver().a(f1401a.getApplicationContext());
    new ConnectStateReceiver().a(f1401a.getApplicationContext());
    l.c();
    if (l.a(context) != null) {
        String strA = m.a(context, "firstPowerOn", "");
        if (strA != null && !strA.isEmpty()) { b.a(f1401a, "B"); }
        else { b.a(f1401a, "F"); m.b(context, "firstPowerOn", "firstPowerOn"); }
    }
}
```

`OnBootReceiver` 在清单里是 `android:exported="true"` 且只声明了 `BOOT_COMPLETED` 与 `QUICKBOOT_POWERON` 两个 action 的 intent-filter。显式指定组件名发广播时，intent-filter 不参与匹配，所以任意 action 都能送达，落进 else 分支直接跑 `b.a(ctx,"B")`。

另外注意 `onReceive` 里从 prefs 读 `preference_enable_log` 的这行。事务码 4 写过之后，目标进程只要收到任何一条本广播就会把 `e.f1332a` 置真，日志门控随之打开，这也是为什么 logcat 能作为旁证。

## 六 事务码 2 与 3 的具体后果

来源 `jadx/sources/com/mobiletools/systemhelper/service/RegisterHelperService.java`

```java
public void a(int i) {
    m.b(RegisterHelperService.this.f1420b, i);
    m.a(RegisterHelperService.this.f1420b, (i * 8) / 5);
    m.c(RegisterHelperService.this.f1420b, (i * 9) / 5);
}
public void b() { m.a(); }
```

来源 `jadx/sources/c/d/a/b/m.java`

```java
public static void b(Context context, long j) { b(context, "scheduleInterval", j); }
public static void a(Context context, long j) { b(context, "appInfoInterval", j); }
public static void c(Context context, long j) { b(context, "signalInfoInterval", j); }

@SuppressLint({"SdCardPath"})
public static void a() {
    File file = new File("/data/data/com.mobiletools.systemhelper/shared_prefs/"
            + "com_mobiletools_systemhelper_preference.xml");
    if (file.exists()) { file.delete(); }
}
```

事务码 2 传 `i` 会同时把 24h 定时、6h 应用统计、6h 信号采样三个周期一起改，传入 `1000` 即全部变秒级。事务码 3 删的是整个 prefs 文件，含待补传相关的键和 `firstPowerOn`。

## 七 权限侧的旁证

来源报告第三章实机 `dumpsys` 与 `privapp-permissions-systemhelper.xml`

```
/system/etc/permissions/privapp-permissions-systemhelper.xml
    READ_PRIVILEGED_PHONE_STATE
    READ_PRECISE_PHONE_STATE
    PACKAGE_USAGE_STATS
    MODIFY_PHONE_STATE      <- 重复出现两次，且清单并未申请
```

白名单里 `MODIFY_PHONE_STATE` 重复且无效，说明这份配置缺乏系统性复核。与本次漏洞的关联在于：同一套「配置漏检」习惯同时体现在白名单和组件导出上，属组织性问题而非单点笔误。

## 八 还原依据，为什么写回默认值就够

目标侧 5 个事务码里只有 code 5 有返回值，读的是 `preference_enable_log`，**没有读 `serverAddress` 的接口**。所以无法「先读旧值再写回」，只能写回内置默认值。

来源 `jadx/sources/c/d/a/b/e.java`

```java
public static String l = "http://dm.wo.com.cn:18080/register";
public static boolean f1333b = false;      // 全工程无赋值点
```

来源 `jadx/sources/c/d/a/b/m.java`

```java
public static String d(Context context) {
    return e.f1333b ? e.l : a(context, "serverAddress", e.l);
}
```

`a(context, "serverAddress", e.l)` 的第二个参数是默认值，即 `serverAddress` 键不存在时返回 `e.l`。把 `serverAddress` 写成 `e.l` 之后，取值与键不存在时完全相同，因此行为等价于「从未被覆写」，不留可观测差异。

这也是 PoC 的还原逻辑用 `probe.DEFAULTURL` 而不是「读到的旧值」的依据。

## 九 修复对应的最小改动

清单侧：

```xml
<service android:exported="true"
         android:permission="com.mobiletools.systemhelper.permission"
         android:name="com.mobiletools.systemhelper.service.RegisterHelperService">
```

`com.mobiletools.systemhelper.permission` 已经在清单里定义为 `protectionLevel="signature"`，直接引用即可，无新增权限。

代码侧，加一层 uid 兜底：

```java
public IBinder onBind(Intent intent) {
    if (Binder.getCallingUid() != Process.myUid()) { return null; }
    return new a();
}
```

更彻底的做法是删掉 `serverAddress` 这个运行时可写入口，把上报地址改成编译期常量或受签名校验的配置源。
