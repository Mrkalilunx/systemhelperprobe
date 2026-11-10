# SystemHelper 3.0.0 逆向分析报告

分析对象：`data/SystemHelper_3.0.0-20231222.apk`
包名：`com.mobiletools.systemhelper`
报告日期：2026-11-10
修订：2026-11-11，补入实机复现结果，修正三处推断（§8.3.1 加密强度、§8.3 哈希作用、§十 上报门控）。
修订：2026-11-12，加密链的成本核算与设计错位移入 [`exploit.md`](exploit.md)，本报告只保留弱点的结论。

全文的加签、加密与截获后恢复明文的完整推演，含五档穷举成本，见 [`exploit.md`](exploit.md)。本报告第 8 章只给结论与实测数据。

本报告沿用同一体例，全文标注三类内容：

- 「观测」= 直接从样本字节、反编译代码、字符串、实机 `dumpsys`/`getprop` 输出中读到的内容
- 「推断」= 基于观测的逻辑演绎，未做全链路运行时验证
- 「未知」= 当前证据不足以判断

## 关于本文的脱敏处理

本文对测试机标识做了处理，避免把个人设备的敏感信息带入公开文档：

- 机型统一写作「测试机」，不回填 `Build.MODEL` 原值
- 不记录 `IMEI`/`IMSI`/`ICCID`/`MAC`/`SSID`/序列号等任何设备唯一标识
- 载波标识只保留 `MCC+MNC`（属公开运营商编号，不具设备指向性）
- 示例 JSON 中的字段值若与本机一致，已改为占位写法

文中出现的十六进制业务数据均为**加密后的密文或哈希值**，无法反推设备信息。

# 一、结论摘要

1. 这是**中国联通电信终端管理（DM）客户端**，包名、证书、服务器、上报字段全部指向联通侧 DM 平台。它随定制 ROM 预装进 `/system/priv-app`，以 `sharedUserId com.mobiletools.systemhelper.uid` 运行（本机实得 uid 10088）。
2. 业务单一：把设备/双卡/小区/信号/应用使用情况打包成 JSON，AES 加密 + RSA 加签后 POST 到 `http://dm.wo.com.cn:18080/register`；另用 `http://dm.wo.com.cn:18080/public/ip` 取出口 IP。
3. **上报有运营商门控**，但门控比「必须是联通卡」宽：`(WiFi 已连 && MNC 以 460 开头) || (!漫游 && 数据卡为联通)`。因此连着 WiFi 且插任意中国大陆运营商卡（移动、联通、电信都算）都会真正上报；只有走移动数据时才要求联通卡。门控不通过时写入本地 SQLite 队列，等条件满足再补传（观测 + 实机验证）。
4. 报文封装是可完全复现的：`key = MD5(payload)`，`body = AES/ECB/PKCS5(key, payload)`，`sign = Base64(RSA/ECB/PKCS1(pub.cer, key))`，以 `?ver=5.0&model=&manuf=&sign=` 拼到 URL 上。已用 Python 实测复现 roundtrip。
5. `pub.cer` 是 **1024-bit RSA 自签证书**（`CN=UNICOM, O=UNICOM, C=CN`，有效期 2019-05-24 至 2119-04-30）。用 1024 位密钥 + PKCS#1 v1.5 + MD5 摘要，加签强度按现代标准已属弱。
6. 全链路走 **明文 HTTP**（`android:usesCleartextTraffic="true"`，端口 18080）。报文虽有应用层加密，但传输层无保护，且签名方案是「私钥解签 = 摘要」的可逆校验模式。
7. 调度靠 `AlarmManager.setExactAndAllowWhileIdle`，共 5 条独立闹钟（开机、SIM、定时、应用信息、信号信息），周期 24h / 6h，带 0~9 秒随机抖动。
8. 定位用内嵌百度 SDK（`liblocSDK8b.so` + `libindoor.so`），`Battery_Saving` 模式、`bd09ll` 坐标系，仅在系统定位开关打开时启用，用于给小区信息补经纬度。
9. **服务端现不可达**：`dm.wo.com.cn:18080` 两个路径均返回 `403 Forbidden`，响应头 `WZWS-RAY ... reason:UrlACL`，是联通侧 WAF 按 URL 做的 ACL 拦截。因此「服务器下发指令」「响应体语义」类问题无法取证。
10. 未见 `DexClassLoader`/`Runtime.exec`/`ProcessBuilder` 等动态加载或命令执行，也未见上报之外的远控能力。它的能力边界是**采集 + 上报**，不是远控木马；但采集面（IMEI/IMSI/ICCID/精确小区/全量应用使用与流量/经纬度）确实属于运营商级敏感数据。
11. 两个原生库已完成 **Hex-Rays 全量反编译**（第十二章，1383 + 3872 个函数，产物归档于 `work/systemhelper/ida/`），所有靠汇编得出的原生层结论均获指令级复核。
12. 原生库层已逐符号核查（第十二章）：`liblocSDK8b.so` 是百度定位 SDK 的加解密内核，无网络导入、无动态加载；`libindoor.so` 依赖两个包内与系统内都不存在的 so，**加载必然失败**，其内含的 `ptrace` 反调试与 `system()` 解压调用在本样本中全部不可达。so 层不参与联通 DM 报文的加签加密，唯一实质发现是**百度 SDK 的下行 AES 密钥硬编码在 so 里、全设备共用**。

# 二、样本与签名指纹

## 2.1 文件指纹（观测）

| 项目 | 值 |
|---|---|
| 文件名 | SystemHelper_3.0.0-20231222.apk |
| 大小 | 3,169,243 字节 |
| SHA-256 | `3465830c2e56067090fc8549632d532a30bee47a315e0b7935fd3ab136120d09` |
| 包名 | `com.mobiletools.systemhelper` |
| versionName | 3.0.0-20231222 |
| versionCode | 31 |
| minSdkVersion | 31 |
| targetSdkVersion / compileSdkVersion | 33 / 33 |
| ZIP 条目总数 | 407 |
| sharedUserId | `com.mobiletools.systemhelper.uid` |

## 2.2 内部组件指纹（观测）

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `classes.dex` | 1,510,664 | `1797026ded8c326fd25e1ba7473009b785d1c18247cb6c502636c657b9d34923` |
| `assets/pub.cer` | 596 | `810c0122ba6af7a4b6a5921fdbbbf9197fb2e0b2e82de0c5aa40d28f1b7c6501` |
| `lib/arm64-v8a/liblocSDK8b.so` | 368,568 | `07e9f2d05ed8a4c33ca5c496c9cf93b1b15d6d3f635d16a8f541dd8b672d07bc` |
| `lib/arm64-v8a/libindoor.so` | 1,596,896 | `71e059853664154dc559ced2069eb189fe9ce24ea944e8fc8dcbcaa6d9f22024` |

只有 `arm64-v8a` 一个 ABI。`libindoor.so` 体积是定位 SDK 的 4 倍多，属百度室内定位模型资源库。

## 2.3 签名（观测）

```
V2 Signer: certificate DN: CN=NewDM, OU=RI, O=CU, L=BJ, ST=BJ, C=86
SHA-256 digest: 874b8ca2297f53a373b1b935c134cb0eb1ff7381e54491b88c643a6b9c46db77
SHA-1   digest: 0d0b1f90182391c77504b843dd3937b23d749ae6
RSA 2048
```

只有 v2 签名块，无 v1/v3。`META-INF/MANIFEST.MF` 内容仅 3 行（`Manifest-Version`、`Built-By: Generated-by-ADT`、`Created-By: Android Gradle 3.6.0`），没有逐条目摘要，是典型的 Gradle v2-only 打包产物。

证书 DN 里 `O=CU`（China Unicom）、`CN=NewDM`、`OU=RI` 直接暴露了用途与归属（推断，证据强：命名与业务完全自洽）。

## 2.4 内嵌加签公钥证书（观测）

```
subject = C=CN, ST=BJ, L=BJ, O=UNICOM, OU=UNICOM, CN=UNICOM
issuer  = 同上（自签）
serial  = 528B9360
notBefore = 2019-05-24 08:44:27 GMT
notAfter  = 2119-04-30 08:44:27 GMT
Signature Algorithm: sha256WithRSAEncryption
Public-Key: (1024 bit)
```

1024 位密钥在 2019 年签发已属偏弱，现在（2026）按 NIST 口径早就该退役（推断）。

# 三、预装与权限事实（实机观测）

设备：测试机，Android 13（SDK 33），制造商 Xiaomi（机型已隐去）。

| 事实 | 值 |
|---|---|
| 安装位置 | `/system/priv-app/SystemHelper/SystemHelper.apk` |
| 实机 APK SHA-256 | 与本地样本一致 |
| uid / sharedUser | 10088 / `com.mobiletools.systemhelper.uid` |
| flags | `SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA` |
| privateFlags | 含 `PRIVILEGED` |
| apkSigningVersion | 2 |
| 首次安装时间 | 1970/2009 时间戳，属系统镜像预置 |
| dexopt 状态 | `verify`（`SystemHelper.odex` 24KB / `vdex` 1402KB） |

privapp 白名单 `/system/etc/permissions/privapp-permissions-systemhelper.xml`：

```xml
<privapp-permissions package="com.mobiletools.systemhelper">
    <permission name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
    <permission name="android.permission.READ_PRECISE_PHONE_STATE"/>
    <permission name="android.permission.PACKAGE_USAGE_STATS"/>
    <permission name="android.permission.MODIFY_PHONE_STATE"/>
    <permission name="android.permission.READ_PRECISE_PHONE_STATE"/>
</privapp-permissions>
```

两处值得记录（观测）：

- 白名单里 **`MODIFY_PHONE_STATE` 重复出现一次**（第 2、5 行同名），且**清单并未申请**该权限，`dumpsys` 里也查不到授权记录。这是一条无效声明，说明白名单维护得比较随意（推断）。
- 白名单声明了 `MODIFY_PHONE_STATE` 却没有使用，反过来印证代码里没有改机/改网能力。

运行时权限全部默认授予，无须用户点同意（观测）：

```
ACCESS_FINE_LOCATION:        granted=true  GRANTED_BY_DEFAULT
ACCESS_COARSE_LOCATION:      granted=true  GRANTED_BY_DEFAULT
ACCESS_BACKGROUND_LOCATION:  granted=true  GRANTED_BY_DEFAULT | RESTRICTION_SYSTEM_EXEMPT
READ_PHONE_STATE:            granted=true  GRANTED_BY_DEFAULT
READ_EXTERNAL_STORAGE:       granted=true  GRANTED_BY_DEFAULT | RESTRICTION_SYSTEM_EXEMPT
```

签名级/普通权限（`install permissions`）全部 `granted=true`，含 `READ_PRIVILEGED_PHONE_STATE`、`READ_PRECISE_PHONE_STATE`、`PACKAGE_USAGE_STATS`、`QUERY_ALL_PACKAGES`、`SCHEDULE_EXACT_ALARM`、`RECEIVE_BOOT_COMPLETED`。

这套权限组合的含义很明确（推断）：`READ_PRIVILEGED_PHONE_STATE` 用于绕过普通应用拿不到 IMEI/IMSI 的限制；`PACKAGE_USAGE_STATS` + `QUERY_ALL_PACKAGES` 用于枚举全量已安装应用并统计使用时长；`SCHEDULE_EXACT_ALARM` 让定时上报不受 Doze 影响。

# 四、组件与触发面

## 4.1 清单结构（观测）

| 类型 | 组件 | exported | 说明 |
|---|---|---|---|
| Activity | `.Activity.TestActivity` | true | 面板，action `com.mobiletools.systemhelper.activity.testactivity` |
| Receiver | `.control.OnBootReceiver` | true | `BOOT_COMPLETED`、`QUICKBOOT_POWERON`，`priority=2147483647` |
| Receiver | `.control.SIMStateReceiver` | true | `SIM_STATE_CHANGED` |
| Receiver | `.control.ConnectStateReceiver` | true | `CONNECTIVITY_CHANGE` |
| Receiver | `.control.ScheduleRegisterReceiver` | false | 仅内部闹钟触发 |
| Receiver | `.control.AppInfoRegisterReceiver` | false | 仅内部闹钟触发 |
| Receiver | `.control.SignalInfoRegisterReceiver` | false | 仅内部闹钟触发 |
| Service | `.service.RegisterHelperService` | true | Binder `IRegisterHelperService` |
| Service | `.service.RegisterIntentService` | false | IntentService，未在代码中启动 |
| Service | `.service.RegisterJobService` | false | 绑 `BIND_JOB_SERVICE`，`onStartJob` 只打日志 |
| Service | `com.baidu.location.f` | false | 百度定位，`:remote` 独立进程 |

`priority=2147483647`（Integer.MAX_VALUE）用于抢占开机广播的最前位（观测）。

## 4.2 Binder 接口能力（观测）

`com.mobiletools.systemhelper.service.IRegisterHelperService` 5 个事务码：

| code | 方法 | 效果 |
|---|---|---|
| 1 | `a(String)` | 覆盖服务器地址（`serverAddress`） |
| 2 | `a(int)` | 同时改三个间隔：`appInfoInterval=i`、`scheduleInterval=i*8/5`、`signalInfoInterval=i*9/5` |
| 3 | `b()` | 删除 `shared_prefs/com_mobiletools_systemhelper_preference.xml` |
| 4 | `a(boolean)` | 开关调试日志 `preference_enable_log` |
| 5 | `a()` | 读回日志开关 |

这是**外部可改上报目的地**的接口面（观测）。服务 `exported=true` 且没有 `android:permission` 保护，任何应用都能 bind 后把 `serverAddress` 改成任意地址（推断，风险点，见第十五章）。

`c.c.a.a` 是格力 `com.gree.telephonymanager.IGreeTelephonyManager` 的 AIDL 存根，仅在 `RegisterIntentService` 的 `ServiceConnection.onServiceConnected` 里赋值给 `e.x`，**全代码没有任何 bindService 调用**，属遗留死代码（观测）。

## 4.3 触发入口汇总（观测）

| 入口 | 传入 RegType | 判据 |
|---|---|---|
| `OnBootReceiver`，`BOOT_COMPLETED`/`QUICKBOOT_POWERON` | 先排 4 分钟闹钟，回落后再跑 | 见 4.4 |
| 同上，非开机分支 | `B` 或 `F` | `firstPowerOn` 为空 → `F` 并写入标记；非空 → `B` |
| `SIMStateReceiver`，`SIM_STATE_CHANGED` | 先排 6 分钟闹钟 | — |
| 同上，闹钟回落路径 | `T` | — |
| `ScheduleRegisterReceiver` | `S` | 24h 定时 |
| `AppInfoRegisterReceiver` | `A` | 6h 定时 |
| `SignalInfoRegisterReceiver` | `R` | 6h 定时 |

`RegType=H` 在本版本**没有任何产生点**（观测：全局搜索只在 `a$a` 里作为百度经纬度字符串后缀 `"H"` 出现）。上一轮若把 `H` 归为触发类型，应作废；`H` 不参与 RegType 语义。

## 4.3.1 被忽略的启动入口：`DMApplication`（观测）

除七个 Receiver 与 `RegisterHelperService` 之外，还有一个更早的入口：清单里
`android:name="com.mobiletools.systemhelper.control.DMApplication"` 指定了自定义 `Application`。
它只有 23 行，但作用不可忽略：

```java
public class DMApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        i.a("DMApplication", "onCreate--->");
        if (Build.VERSION.SDK_INT >= 31) {
            c.d.a.a.a.e(this);        // 注册 TelephonyCallback
        }
    }
}
```

`c.d.a.a.a.e(Context)` 是「给两个卡槽各建一个 `createForSubscriptionId` 的 `TelephonyManager` 并
`registerTelephonyCallback`」的那个方法（见 11.1）。由于 `minSdkVersion=31`，这个条件恒成立，等价于：

**进程一启动就注册信号监听，不依赖任何闹钟或广播。**

这一点改变了「什么时候开始采集」的答案：此前只能从闹钟时序推论，实际上只要进程被拉起（开机广播、`RegisterHelperService` 被 bind、`TestActivity` 被打开、闹钟触发）就已经在监听信号强度了。
调用点全量（观测，smali）：

| 调用方 | 时机 |
|---|---|
| `DMApplication.onCreate` | 进程启动，最早 |
| `RegisterHelperService.onCreate` | 服务创建 |
| `AppInfoRegisterReceiver` / `SIMStateReceiver` / `ScheduleRegisterReceiver` / `SignalInfoRegisterReceiver` / `OnBootReceiver` | 各自 `onReceive` |
| `TestActivity` | 打开面板 |
| `c.d.a.a.l.a(Context)` | 需要设备信息时再补一次 |

`e()` 内部有 `if (e.e)` 守卫，且用 `static` 字段判重（`e.f` / `e.g` 非空则跳过），所以重复调用不会重复注册。

## 4.4 开机分支的真实顺序（观测，smali 校验）

`OnBootReceiver.onReceive` 里先判断 action：

```
BOOT_COMPLETED / QUICKBOOT_POWERON
  → c.d.a.b.a.b(ctx, 240000)     // 4 分钟后回调 OnBootReceiver 自己
  → a.d(ctx, scheduleInterval)   // 24h 定时
  → a.a(ctx, appInfoInterval)    // 6h 应用信息
  → a.e(ctx, signalInterval)     // 6h 信号
  → return
其他 action（即 4 分钟闹钟回落）
  → new SIMStateReceiver().a(ctx)      // 动态注册 SIM 监听
  → new ConnectStateReceiver().a(ctx)  // 动态注册网络监听
  → 读 firstPowerOn：空 → b.a(ctx,"F") 并写入 "firstPowerOn"
                     非空 → b.a(ctx,"B")
```

也就是说 **`B` 是「非首次开机」，`F` 是「首次开机」**，且 `F` 只发生一次（写入标记后永不再来）。`F` 的报文在 `RegisterThread` 里走专用分支：写进 `typef` 表而不是 `dmregister` 表（观测，见第十三章）。

# 五、调度时序（观测）

`c.d.a.b.a` 全部 5 个方法都是同一形态：

```java
AlarmManager.setExactAndAllowWhileIdle(
    AlarmManager.ELAPSED_WAKEUP,          // 2
    SystemClock.elapsedRealtime() + delay,
    PendingIntent.getBroadcast(ctx, 0, new Intent(ctx, XxxReceiver.class), 0xC000000));
```

`0xC000000` = `FLAG_UPDATE_CURRENT(0x8000000) | FLAG_IMMUTABLE(0x4000000)`。用 `ELAPSED_WAKEUP` 而非 `RTC_WAKEUP`，说明按「开机后经过时间」计时，与墙上时钟无关。

| 闹钟 tag | 周期来源 | 常量 |
|---|---|---|
| `OnBootReceiver` | 开机延迟 | `240000` = 4 分钟 |
| `SIMStateReceiver` | SIM 就绪等待 | `360000` = 6 分钟 |
| `ScheduleRegisterReceiver` | `scheduleInterval` | `86400000` = 24h + rand(0..9)*1000 |
| `AppInfoRegisterReceiver` | `appInfoInterval` | `21600000` = 6h + rand(0..9)*1000 |
| `SignalInfoRegisterReceiver` | `signalInfoInterval` | `21600000` = 6h + rand(0..9)*1000 |

随机抖动实现（观测，`m.c`）：

```java
int r = new Random().nextInt(10);
return getLong("scheduleInterval", e.n + r * 1000L);  // e.n = 86400000
```

抖动只在**默认值**上生效：一旦 `RegisterHelperService` 写入了 `scheduleInterval`，后续读取直接用存储值，不再抖动（观测：三元表达式的位置在默认值参数里）。

实机旁证（观测，`dumpsys alarm`）：

```
ELAPSED_WAKEUP #24: Alarm{... com.mobiletools.systemhelper}
  tag=*walarm*:com.mobiletools.systemhelper/.control.SignalInfoRegisterReceiver
  exactAllowReason=permission  whenElapsed=+58m44s
ELAPSED_WAKEUP #73: tag=.../.control.AppInfoRegisterReceiver    whenElapsed=+18h58m44s
ELAPSED_WAKEUP #74: tag=.../.control.ScheduleRegisterReceiver   whenElapsed=+18h58m50s
```

`+18h58m` 与 24h 的差值说明写存储的 `scheduleInterval` 被改过（或上次触发已消耗部分周期），`exactAllowReason=permission` 表明 `SCHEDULE_EXACT_ALARM` 已授予。历史统计段显示只有 `OnBootReceiver`（-4h57m）与 `SIMStateReceiver`（-4h55m）真正唤醒过，与「开机后 4 分钟 / 6 分钟两条链」完全吻合（观测）。

进程当前不在跑（`current` 无该包），只有 alarm 残留，说明被系统按需唤醒后回收（观测 + 推断）。

# 六、主流程编排

`c.d.a.a.l.a(Context, String regType)` 是唯一的编排入口（观测）：

```
新建 control.b，b.K = regType
c(ctx, bVar)                       // 采设备/卡/网络基础信息
if (regType != "T") {
    a(ctx, bVar);                  // SIM 槽位交换 + 运营商合法性清洗
    b(ctx, bVar);                  // 同上（历史遗留重复调用）
} else {
    if (!a(ctx,bVar) && !b(ctx,bVar)) return bVar;   // SIM 未变化则不上报
}
a(bVar);                           // ICCID 洗白 + MD5
if (regType == "A") {
    e.e ? new e(ctx,bVar,callback)  // 查应用使用统计，回调后再发
        : new f(ctx,bVar)           // 权限未开则直接发（AppInfo 为空）
} else if (regType == "R") {
    从 signal 库取全部记录 → bVar.P
    有记录 → 清库 → c/f 线程
    无记录 → f 线程
} else {
    c/f 线程
}
.start()
```

`c` 与 `f` 的分叉由 `e.f1334c` 决定（`c` = 先补 IPv4/IPv6 再发，`f` = 直接发），而 `e.f1334c` **全工程无赋值，恒为 false**（观测），所以实际永远走 `f` 分支，IPv4/IPv6 字段恒为空。`c.d.a.b.c` 那个 IPv6 枚举实现是死代码。

## 6.1 上报前的三步清洗（观测，`a(bVar)` 与 `m`）

第一步，双卡交换：若 `IMEI1 > IMEI2`（字符串比较）则整体交换两槽的 IMEI/ICCID/IMSI/MNC/网络/TAC/CID/PCI/VoLTE/5G/VoNR，并把 `DataSlot` 从 `1↔2` 互换。目的是把「物理槽位」规范成「主卡在前」（推断）。

第二步，非法运营商洗白：只要有一个条件成立就**清空全部 26 个卡相关字段**：

```
ICCID1 非空且不以 "89" 开头
ICCID2 非空且不以 "89" 开头
MNC1  非空且不以 "460" 开头
MNC2  非空且不以 "460" 开头
```

即：非中国（非 460）或非 SIM（非 89 开头，如 eSIM 的 8986xx 是 89 开头，符合）的卡，一律不上报卡信息。

第三步，ICCID 脱敏：若 `m.c(MNC, ICCID)` 返回 false（即 ICCID 不以 `898601/898606/898609` 开头），则对 ICCID、IMSI、CID、TAC 做 **SHA-256 十六进制小写** 处理（`c.d.a.b.j.a`）。也就是**联通卡上报明文，别的卡上报哈希**（观测 + 推断）。

# 七、上报 JSON 字段字典

`control.b.a()` 组装，共 **40 个顶层键**（观测，含 `SubType`，smali 交叉核对无误）。空值填充规则：字符串型默认 `""`，`Manuf/Model/HWVersion/SWVersion/OS/OSVersion/AccType` 默认 `"Unknown"`。

## 7.1 设备与系统

| 键 | 来源 | 说明 |
|---|---|---|
| `Manuf` | `Build.MANUFACTURER` 或型号→厂商映射表 | 厂商 |
| `Model` | `Build.MODEL` | 型号 |
| `HWVersion` | `ro.hardware.version`；小米走 `ro.miui.cust_hardware`（`2106118C` 例外走 `ro.build.hardware.version`） | 硬件版本 |
| `SWVersion` | 小米走 `miui_version_name` 或 `ro.build.version.incremental` 拼「MIUI x.y.z(n)」；其他走 `Build.DISPLAY` | 软件版本 |
| `OS` | 固定 `"Android"` | 系统名 |
| `OSVersion` | `Build.VERSION.RELEASE` | 系统版本 |
| `DeviceType` | 默认 `000005`，nubia 为 `000004`；vivo 路径按 5G 属性 `000005/000004`；空则 `000` | 终端类型编码 |
| `Time` | `SimpleDateFormat("yyyy-MM-dd HH:mm:ss")` | 本地时间 |
| `ClientVersion` | `PackageManager` 的 versionName | 样本内为 `3.0.0-20231222` |
| `SpecVersion` | 硬编码 `"5.0"` | 规范版本 |

## 7.2 双卡信息（1/2 各一套，共 22 键）

| 键 | 来源 |
|---|---|
| `IMEI1/2` | `miui.telephony.TelephonyManager.getImeiForSlot`（小米）或 `TelephonyManager.getImei(slot)` |
| `ICCID1/2` | `getSimSerialNumber()`（非联通卡改写为 SHA-256） |
| `IMSI1/2` | `getSubscriberId()`（非联通卡改写为 SHA-256） |
| `MNC1/2` | `MCC+MNC` 拼串，取自 `CellIdentity*.getMccString()+getMncString()` |
| `NetworkType1/2` | `GSM` / `WCDMA` / `TD-SCDMA` / `CDMA` / `LTE` / `NSA` / `SA` |
| `TAC1/2` | LTE `getTac()`、NR `getTac()`、GSM/WCDMA `getLac()` |
| `CID1/2` | LTE `getCi()`、NR `getNci()`、GSM/WCDMA `getCid()`、CDMA `getBasestationId()` |
| `PCI1/2` | LTE/NR `getPci()`，其他制式为空 |
| `VolteEnabled1/2` | `ImsManager.isAdvancedCallingSettingEnabled()` → `1/0/-1` |
| `5GEnabled1/2` | `Settings.Global.preferred_network_modeN` 落在 23..33 → `1/0` |
| `VoNREnable1/2` | NR 登记信息串里是否含 `mVopsSupport = 1` → `1/0` |

`NSA` / `SA` 的判定方式很土：把 `NetworkRegistrationInfo.toString()` 转成字符串，看里面有没有 `isEnDcAvailable = true`（有则 NSA）或 `mVopsSupport = 1`（无则 VoNR=0）（观测）。

## 7.3 网络与附属对象

| 键 | 来源 |
|---|---|
| `DataSlot` | `SubscriptionManager.getActiveDataSubscriptionId()` 命中 subId0/subId1 → `1/2`，否则 `0` |
| `AccType` | `Mobile` / `WiFi` / `Disconnected`（需 `ACCESS_NETWORK_STATE`） |
| `IPv4` | 取 `public/ip` 返回值，但该线程恒不执行（`e.f1334c` 恒 false）→ 恒空 |
| `IPv6` | 同上 |
| `SubType` | `SubType` 不是字符串而是**嵌套 JSONObject**：`c.d.a.b.h.b(context)` 返回 `{RAM, ROM, FREE}`，三个值都形如 `"8G"` |
| `SigInfo` | JSONArray，见 7.4 |
| `AppInfo` | JSONArray，见 7.5 |

`SubType` 三个值的真实算法（观测，`c.d.a.b.h`）：

| 键 | 方法 | 算法 | 已知偏差 |
|---|---|---|---|
| `RAM` | `h.a(Context)` | 先读 `ro.boot.dram_info`（逗号分割取最后一段、剥掉非数字），失败则退到 `ActivityManager.MemoryInfo.totalMem` 并按 2 GB 档位上取整（>30 GB→32、>28→30…） | 前者单位是 G，后者被归到偶数档，两者结果可能不同；文档没说哪个优先命中 |
| `ROM` | `h.b()` | `StatFs(/data)` 的总块数 × 块大小，再取**比它大的下一个 2 的幂** | 不是真实容量，也不是就近上取整 |
| `FREE` | `h.a()` | `StatFs(/data)` 的可用块 × 块大小，四舍五入到 G | 是 `/data` 分区，不含 `/sdcard` |

`ROM` 那段的偏差值得写清楚（观测 + 实算）。循环是：

```java
int i = 0;
while (x > 0) {
    int i2 = i + 1;
    if (x < Math.pow(2, i2) && x >= Math.pow(2, i)) break;
    i = i2;
}
return ((int) Math.pow(2, i + 1)) + "G";
```

循环本身找的是 `2^i <= x < 2^(i+1)`，正确；但返回的是 `2^(i+1)` 而不是 `2^i`，
所以对**任何**容量都恒返回值高一整档的结果。实算：

| 真实 `/data` 容量 | 上报 `ROM` |
|---|---|
| 16G | 32G |
| 64G | 128G |
| 128G | 256G |
| 512G | 1024G |

也就是说 `ROM` 字段系统性偏大一倍，且恰好是「下一档」——`ROM=128G` 的实际含义是「64G 以上、128G 以下」。
对服务端做机型识别有影响（容量档位错一位），不影响流程。

## 7.4 `SigInfo` 元素结构（观测，`c.d.a.b.o.a()`）

30 个键，值全为字符串：

```
Time, IMEI, MSISDN, MNC, IMSI, TAC, CID, PCI, NetworkType,
ARFCN, Bands, Bandwidth, CQITableIndex, CQIIndex,
RSRP, RSRQ, SINR, CSIRSRP, CSIRSRQ, CSISINR,
Uspeed, Dspeed, CallDisconnectCause, DataFailCause, EPSFallback,
LONGITUDE, LATITUDE, ALTITUDE, SPEED, BEARING
```

`a()` 有前置校验：`IMEI / MNC / IMSI / TAC / CID / PCI / NetworkType` 任一为空即返回 `null`，这条记录被丢弃。这就解释了为什么非 460 卡（字段被洗成 `"111"` 或空）产不出信号记录。

`MSISDN` 恒空（`oVar.e = ""`，`oVar.n = ""`，`oVar.m = ""`）。`Uspeed/Dspeed` 恒空（无赋值点）。

## 7.5 `AppInfo` 元素结构（观测，`c.d.a.b.b.a()`）

11 个键：

```
appLabel, pkgName, Time, runTime, tx1, rx1,
tx2, rx2, totalData1, totalData2, totalDataWiFi
```

采集逻辑（`control.e`）：

- `UsageStatsManager.queryAndAggregateUsageStats(now - appInfoInterval, now)`，按 `getTotalTimeInForeground` 降序
- 每项取 前台时长（分钟）/ 该 UID 卡1 流量（KB，`NetworkStatsManager.querySummary(0, imsi1, ...)`）/ 卡2 流量（KB）/ WiFi 流量（MB，`querySummary(1, null, ...)`）
- 过滤条件：`pkgName` 以 `com.android` 开头的全部剔除（`l$a.a()` 里 `!startsWith("com.android")`）

上报的是**全量已安装应用的使用时长与流量明细**，这是本样本最敏感的一块（推断）。

# 八、加签与加密（已实测复现）

## 8.1 算法（观测）

`control.f.a(b)` 组装：

```java
String payload = bVar.a();                        // 明文 JSON
byte[] digest  = c.d.a.b.c.a(payload);            // MD5(payload.getBytes("UTF-8"))
String sign    = URLEncoder.encode(
                   c.d.a.b.c.a(c.d.a.b.c.a(ctx, digest)),  // Base64(RSA(pub.cer, digest))
                   "utf-8");
String url     = m.d(ctx) + "?ver=5.0"
               + "&model=" + URLEncoder.encode(bVar.f1411b, "utf-8")
               + "&manuf=" + URLEncoder.encode(bVar.f1410a, "utf-8")
               + "&sign="  + sign;
byte[] body    = c.d.a.b.c.a(payload, digest);    // AES/ECB/PKCS5(key=digest, payload)
g.a(url, body, digest);
```

`c.d.a.b.c` 的三个重载（注意 RSA 并不在本类，见下）：

- `a(String)` → `MD5.digest(s.getBytes("UTF-8"))`
- `a(Context, byte[])` → 读 `assets/pub.cer` → 交给 `c.d.a.b.k`（`RSAHelper`）解析并加密
- `a(String, byte[])` → `SecretKeySpec(key,"AES")` + `AES/ECB/PKCS5Padding` 加密

RSA 的实际实现在 `c.d.a.b.k`（`RSAHelper`），两个方法：

```java
public Key a(InputStream in) {           // 解析证书取公钥
    return ((X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(in)).getPublicKey();
}
public byte[] a(Key key, byte[] data) { // 用公钥加密
    Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    c.init(Cipher.ENCRYPT_MODE, key);
    return c.doFinal(data);
}
```

即 `c.d.a.b.c` 只是外壳，`pub.cer` 的读取与 `RSA/ECB/PKCS1Padding` 都在 `c.d.a.b.k`。

HTTP 层（`c.d.a.b.g`）：`POST`，`Content-Type: application/encrypted-json`，`Content-Length` 为密文长度，连接超时 10s / 读超时 15s，只认 `200`；`416` 在调用侧被当成功（`if (!ok && code == 416) ok = true`）。

`sign` 的语义是**用公钥加密摘要、服务端用私钥解密后比对**，不是标准的「私钥签名」。因为只有服务端持有私钥，所以签名不可伪造；但这种「可逆校验」在协议设计上属非常规做法（推断）。

## 8.2 Python 复现（观测，已跑通）

```python
import hashlib, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography import x509 as cx509

payload = '{"Manuf":"Xiaomi","Model":"<测试机型号>","RegType":"B"}'
digest = hashlib.md5(payload.encode()).digest()          # 32 hex
p = padding.PKCS7(128).padder()
data = p.update(payload.encode()) + p.finalize()
body = Cipher(algorithms.AES(digest), modes.ECB()).encryptor().update(data)  # 需再 finalize
cert = cx509.load_der_x509_certificate(open('assets/pub.cer','rb').read())
sig  = cert.public_key().encrypt(digest, apad.PKCS1v15())
sign = base64.b64encode(sig).decode()
```

实测输出：

```
key(MD5)  = 2012393ba972d5fb2c038c392dee60c8
sign b64  = T84JEiQD1kmw1Px4qV3QVzPwoBbiYitfhUqwFq95fsBqxrypNKParylcXZEZs3uq1+MUP7cP9oaqU1QH08+j51OsiBkVtCKVZp6BwLflrEpgo5tXnkq1+IuRIsfa0YnC5cw87MAVhaOrGrxwKbG4uvu+cCgYELIhiA+PXyFjSYY=
body len  = 64
pubkey    = 1024 bit
```

64 字节密文 = 57 字节明文 + PKCS5 填充，与 `AES/ECB` 单块行为一致，roundtrip 成立。

## 8.3 弱点（推断 + 实测校验）

- **AES 密钥 = 报文自身 MD5**，密钥完全由明文派生，无盐无 KDF。拿到明文即可验证密钥；反之密钥泄露等于明文泄露，加密层不提供任何机密性增益。
- AES 用 **ECB** 模式，相同明文块产生相同密文块。
- RSA **1024 位 + PKCS#1 v1.5 + MD5 摘要**，三者都是当前应淘汰的组合 `[未知: 服务端是否仍接受，因 WAF 拦截无法验证]`。
- 全链路 **明文 HTTP**，中间人可完整读取 URL 里的 `model/manuf/sign`，可重放 body（`Time` 字段是否会做防重放校验未知）。

### 8.3.1 补充：截获后的明文恢复（实测）

上面第一条说「加密层不提供机密性增益」当时属于推断。已完成实机闭环验证，结论成立，且可给出具体成本。

实测过程：用事务码 4 打开目标日志，触发上报取到完整明文 JSON，再用 `MD5(明文)` 作密钥解环回口捕获的 body，解出的 JSON 与 logcat 明文逐字节一致。

```
AES 密钥 = MD5(明文) = <32 位十六进制，随每条报文变化>
解密结果与 logcat 明文完全一致: True
```

因此，截获者只要能重建明文模板，就能绕过 RSA 直接恢复内容。可行性与成本：

| 步骤 | 说明 |
|---|---|
| 取明文模板 | 反编译 APK，`control/b.java` 的 `a()` 完整列出 40 个顶层键名与顺序 |
| 定 `Time` 候选 | 用抓包时间戳，秒级枚举 |
| 枚举 `IMEI` | 前 8 位 TAC 可按 `Model` 反查，序列号 6 位，第 15 位由 Luhn 决定 |
| 试解 | 对每个候选算 `MD5`，`AES/ECB/PKCS5` 解 body，首字节为 `{` 且可解析即命中 |

关键点在于**命中判据不需要任何外部信息**。解出的明文若以 `{` 开头、能解析为合法 JSON，就说明密钥对了。校验位就在密文自己身上，这使得穷举可以完全自动化。

单机实测速率（Termux，Python + pycryptodome）：

```
纯 MD5 + AES 解密     约 32,800 次/秒
含模板字符串重建      约 20,244 次/秒
10^6 个候选          约 50 秒（含重建，最坏落在末尾）
```

以真实报文为对象，把 `IMEI1`/`IMEI2` 替换为占位符，从零枚举 IMEI 序列号：

```
尝试 35,205 次  耗时 1.74s  速率 20,244/s
与真实明文完全一致: True
```

在不知道 IMEI、不知道密钥的前提下，1.74 秒恢复完整明文。用 C 或 GPU 可再快 2 到 3 个数量级。

`Time` 窗口实测：以已知明文为模板，仅在 ±5 秒内枚举，一次命中正确密钥。

IMEI 的有效熵只有 6 位，这一点容易被误判：

```
86493605 035204 6
└─TAC──┘ └序列┘ └校验┘
  8 位     6 位   Luhn 自动算出
```

TAC 前 8 位可按 `Model` 公开反查，第 15 位由 Luhn 算法决定、不占熵。因此搜索空间是 `10^6`，不是 `10^7` 或 `10^15`。本次实测 `IMEI2` 序列号只比 `IMEI1` 大 1（`035204` 对 `035205`），属同批次连号分配惯例，两者可绑定枚举，总空间仍为 `10^6`。这是厂商分配规律，非目标应用缺陷，但客观上降低了攻击成本。

限制：

- 每条报文 `Time` 不同，密钥随之不同，须逐条枚举，成本随条数线性增长
- 非联通卡的 `ICCID`/`IMSI` 已被 SHA-256，但哈希不改变搜索空间，攻击者照样枚举原值，只是破解成功后看到的是哈希而非卡号
- 若拿不到设备型号与时间窗口，成本显著上升
- 但需注意：哈希值本身是确定性的，只要该卡不变，同一设备各条报文的 `ICCID`/`IMSI` 哈希值完全一致，反而**降低了需要枚举的变量数**
- **必须看清前提**：上述 1.74 秒是在**已知除 IMEI 外全部字段**的条件下得到的（模板取自目标自身日志）。真实第三方只有密文与请求头，没有这份模板，成本见 `docs/exploit.md`

本节的结论是「密钥派生可被暴力破解」。设计错位、第三方信息面、五档穷举成本与实测数据的边界，统一记录在 [`exploit.md`](exploit.md)，此处不再重复。

### 8.3.2 明文日志通道（实测）

`i.a()` 的打印被 `e.f1332a` 门控，而该开关由事务码 4 直接控制且无权限保护：

```java
// RegisterHelperService.java
public void a(boolean z) {
    e.f1332a = z;
    m.b(RegisterHelperService.this.f1420b, "preference_enable_log", Boolean.valueOf(z));
}
```

打开后，`control/f.java` 的 `i.a("RegisterThread", "register postString：" + strA)` 会把**完整明文**打进 logcat，含 `IMEI1`/`IMEI2` 原值。

但「能打开开关」不等于「能读到日志」，两者主体不同：

| 主体 | 能否读目标日志 | 依据 |
|---|---|---|
| adb / shell（uid 2000） | **能** | 属 `1007(log)` 组 |
| 预置特权应用 | 能 | `READ_LOGS` 为 `signature\|privileged` |
| 普通第三方应用 | **不能** | 非系统签名，也不在 log 组 |

`READ_LOGS` 的 `protectionLevel` 实测为 `signature|privileged|development`。这条通道对普通恶意应用不成立，对具备 adb 权限者成立。

# 九、RegType 语义（观测）

| 值 | 触发 | 报文特征 |
|---|---|---|
| `B` | 开机后（非首次）4 分钟 | 常规 |
| `F` | 开机后（首次，仅一次）4 分钟 | 落库到 `typef` 表，优先补传 |
| `T` | SIM 状态变化后 6 分钟 | 需 ICCID 真变化才发，否则直接 return |
| `A` | 每 6h | 带完整 `AppInfo` |
| `R` | 每 6h | 带 `SigInfo`（清库后批量） |
| `S` | 每 24h | 常规 |

`T` 的分支特殊（观测）：`l.a(ctx, bVar)` 里 SIM 校验失败时直接 `return bVar`，**不启线程、不入库**，等于丢弃。所以 `T` 只在「ICCID 与上次记录不同」时才真正上报。

`SigInfo` / `AppInfo` 在 `b.a()` 里还有一层附加条件（smali 复算）：`DataSlot` 为 `1/2` 的正常分支要求 `RegType=="R"` 才放 `SigInfo`、`RegType=="A"` 才放 `AppInfo`；`DataSlot` 非法（`0`）的分支则要求 `RegType` 为 `R` 或 `""`。两条路径都允许空数组。

# 十、运营商门控（最关键的运行时判据）

`control.f.b(bVar)` 决定「发还是不發」：

```java
if (isIMEIValid(v.g) && isIMEIValid(v.s)) {          // 必须 15 位纯数字
    if (networkConnected) {
        boolean unicom = (isWifi && inChinaNetwork) || (!isChinaNet && isUnicomNetwork);
        if (unicom) {
            if (post(v)) { new HistoryPostThread(ctx).start(); return true; }
        }
    }
    saveToDb(v);                                     // F → typef 表，其余 → dmregister 表
    return false;
}
return false;
```

其中 `m.b(bVar)` 的联通判定（观测）：

```java
DataSlot=="1" 且 (MNC1 ∈ {46001,46006,46009} 或 ICCID1 前缀 ∈ {898601,898606,898609})
DataSlot=="2" 且 (MNC2 ∈ {46001,46006,46009} 或 ICCID2 前缀 ∈ {898601,898606,898609})
```

`l.c(ctx)` 返回 `ServiceState.getRoaming()`（注意：方法名叫「是否中国网」但实际只是**漫游标志**，见 `c.d.a.a.a.a(Context)`）。而且它 `new ServiceState()` 一个全新对象再取漫游位，**恒为 false**（观测），所以 `!l.c(ctx)` 恒真，这个条件在布尔式里不起过滤作用。`m.a(bVar)` 才是真判中国网（MNC 以 `460` 开头）。

实机当时是**中国电信**卡（`gsm.operator.numeric=46011`，`gsm.operator.alpha=中国电信`）。原报告在这里推断「`isUnicomNetwork=false`，WIFI 下 `isWifi && inChinaNetwork` 可成立但仍需 `unicom` 条件，因此本机上报会一直落库不外发」——**这条推断已被实机复现证伪，勿再引用**。

错因：把 `A || (!B && C)` 读成了「必须 C」。`(m.g() && m.a())` 是独立的第一分支，WiFi 已连且 MNC 以 `460` 开头时直接为真，与联通判定无关。`!l.c()` 恒真只说明第二个合取项退化成 `m.b()`，并不能否定第一个分支。

实测更正（同一台机器，电信卡 46011）：

| 条件 | 是否真正 POST |
|---|---|
| WiFi 已连 + 任一 460 运营商卡 | **是，已实测收到 POST** |
| 移动数据 + 联通卡 | 是 |
| 移动数据 + 电信或移动卡 | 否，只落本地库 |

实测做法：打开 WiFi 后由 PoC 覆写 `serverAddress` 到 `127.0.0.1:8080`，再向 `OnBootReceiver` 投递自定义 action，环回口收到 `POST /register?ver=5.0&model=...&manuf=...&sign=...`，单次触发产生 2 条（注册上报与历史补传各一条）。

原报告另一处「没有 `RegisterThread` 的 logcat」的解释也随之更正：那不是门控未通过，而是日志开关 `e.f1332a` 默认 false，`i.a()/i.b()` 直接早退。通过事务码 4 打开后，`adb logcat -s RegisterThread` 能读到完整明文，已实测。

日志开关 `e.f1332a` 默认 false，`i.a()/i.b()` 直接早退，所以除非通过 Binder 事务码 4 打开，否则**什么都打不出来**（观测）。

# 十一、信号采集与百度定位

## 11.1 TelephonyCallback（观测）

`com.mobiletools.systemhelper.control.a` 继承 `android.telephony.TelephonyCallback`，实现三个监听器：

- `SignalStrengthsListener` → 每槽一份 `o` 对象，采集 RSRP/RSRQ/SINR/CSI-RSRP/CSI-RSRQ/CSI-SINR/CQI/CQITableIndex/Bands/Bandwidth
- `CallDisconnectCauseListener` → `a(int)` 里一个 **82 个分支的 `switch`**，映射到 `NOT_DISCONNECTED`/`NORMAL`/`BUSY`/`LOCAL` 等名字，未命中归到 `"INVALID: <code>"`
- `PreciseDataConnectionStateListener` → `getLastCauseCode()` 查 `Map<Integer,String> j`，**357 条** `DataFailCause` 条目（`OPERATOR_BARRED`/`NAS_SIGNALLING` 等）；`lastCauseCode == 0` 时不写入

注册点（观测，`c.d.a.a.a.e`）：只在 `e.e`（用户协议开关）为真时，用 `createForSubscriptionId(subIdN)` 建两个 TelephonyManager，再 `registerTelephonyCallback(mainExecutor, ...)`。

写库节流（观测）：`c.d.a.b.e` 里每个槽各有一对字段——`e.v`/`e.w` 存**上次记录的 `yyyy-MM-dd HH:mm:ss` 字符串**，`e.t`/`e.u` 存**两次记录的时间差（毫秒，初值 −1）**。每次回调先把当前时间与 `e.v`/`e.w` 相减写进 `e.t`/`e.u`，只有 `e.t == -1 || e.t > 360000` 才落一条 `signal` 记录并把 `e.v` 更新为当前时间。即最多每 6 分钟一条，表上限 100 条，即最多覆盖 10 小时。

## 11.2 百度定位（观测）

```java
h.b(true);                       // setAgreePrivacy(true)
LocationClient client = new LocationClient(context);
LocationClientOption opt = new LocationClientOption();
opt.a(LocationMode.Battery_Saving);
opt.a("bd09ll");
opt.a(180000);                   // 扫描间隔 3 分钟
opt.b(300000);                   // 最长等待 5 分钟
opt.g(false); opt.d(true); opt.e(false); opt.b(true);
opt.a(false); opt.f(true); opt.c(true);
client.a(opt);
client.k();                       // start
```

只有 `LocationManager.isLocationEnabled()` 为 true 才启动，否则打「isLocationEnabled false!」直接返回。

回调里按 `c.r()`（定位类型）分支：

- `66`（离线）→ 记为 `offline`
- `61/66/161` → 写 `e.q/e.r/e.s`（经度/纬度/海拔，后缀 `"H"`）
- 其他 → 全部置 `"null"`

经纬度先落到 `o.z/o.A/o.B`，若为空再回填全局缓存 `e.q/e.r/e.s`，保证同一份 SigInfo 尽量带位置。

`bd09ll` 是百度自有坐标系，说明位置数据是给百度生态或按 BD-09 口径入库的；上报到联通侧时未做 WGS-84 转换（观测，无转换代码）。

API Key（观测）：`IGY6EFGRsixbYqk7GeZdAOD2Od3Rj7iF`，直接写死在 `AndroidManifest.xml` 的 `com.baidu.lbsapi.API_KEY` meta-data 里。

# 十二、原生库（.so）分析

包里只有两个原生库，都在 `lib/arm64-v8a/` 下，且都与百度 SDK 相关（观测）：

| 库 | 大小 | sha256 | 构建工具链 | BuildID |
|---|---|---|---|---|
| `liblocSDK8b.so` | 368,568 B | `07e9f2d05ed8a4c33ca5c496c9cf93b1b15d6d3f635d16a8f541dd8b672d07bc` | NDK r22b (7171670)，clang 11.0.5 / LLD 11.0.5 | `192e8b67…95ddf9` |
| `libindoor.so` | 1,596,896 B | `71e059853664154dc559ced2069eb189fe9ce24ea944e8fc8dcbcaa6d9f22024` | NDK r20b (5948944)，clang 8.0.7 | `3178af55…bbe15d` |

两个库均 **stripped**、均 `BIND_NOW`（`FLAGS` 与 `FLAGS_1 NOW` 同时置位）、均无 `RPATH`/`RUNPATH`、均无 `frida`/`xposed`/`magisk`/`TracerPid` 一类反调试指纹字符串。

实机侧（观测）：

```
extractNativeLibs=false
primaryCpuAbi=arm64-v8a
legacyNativeLibraryDir=/system/priv-app/SystemHelper/lib
```

`extractNativeLibs=false` 说明 so 直接从 APK 内 `lib/arm64-v8a/` 映射加载，不走解压目录；`legacyNativeLibraryDir` 指向的 `/system/priv-app/SystemHelper/lib` 在实机上并不存在（`ls` 该目录只有 apk 与 oat）。so 由 `System.loadLibrary` 从 APK 内直接加载，属正常路径。

补充一个范围说明：本样本内嵌的百度定位 SDK 在 Java 常量里一共写了 **17 个硬编码服务端地址**（分布在 `a.a.a.i.d` 的 9 个静态字段，以及 `a.a.a.b.j`/`a.a.a.c.a`/`a.a.a.f.c`/`a.a.a.f.d`/`a.a.a.f.f` 里的字面量）。按功能可分为四组：

| 组 | 地址 | 用途 |
|---|---|---|
| 定位主上行 | `loc.map.baidu.com/sdk.php`、`sdk_ep.php` | 位置/热点上报 |
| 定位辅助 | `loc.map.baidu.com/gpsz`、`cc.php`、`itsdata.map.baidu.com/long-conn-gps/sdk.php` | 卫星/长连接 |
| 离线与室内 | `ofloc.map.baidu.com/offline_loc`（http 与 https 各一份）、`locnu`、`LocBrokerService/do_loc_map_match`、`PlanarStartService/detect_parking_exits`、`loc.map.baidu.com/indoorlocbuildinginfo.php` | 离线包、室内、停车场 |
| 配置与日志 | `loc.map.baidu.com/cfgs/loc/commcfgs`、`cfgs/indoorloc/indoorroadnet`、`check_indoor_data_update`、`api.map.baidu.com/sdkcs/verify`、`daup.map.baidu.com/cltr/rcvr` | 配置下发、校验、WiFi 上报 |

另有一个 `parking.baidu.com/.../getcarportlistforlocation` 属停车场业务。这些地址全在 Java 常量里，so 内**没有任何 URL 字面量**（观测，两库全文 `strings` 检索 `http://`/`https://` 零命中，只有编译器的 llvm 主页串）。所以在「谁在联网」这个问题上，so 只是加密与压缩工具，发起连接的都是 Java 层。

需要修正一处量级判断：17 个地址里有 **5 个在本 APK 中没有发送方**（`sdk_ep.php`、`check_indoor_data_update`、`getcarportlistforlocation`、`do_loc_map_match`、`detect_parking_exits`），只在 `a.a.a.i.d` 里声明过、并被 `parseConfig` 列为可改写项。逐端点的发送方与触发条件见 15.1.2.3。

## 12.1 `liblocSDK8b.so`：百度定位 SDK 的密码学内核

### 12.1.1 结构（观测）

27 个节、9 个程序头、入口 `0x2142C`。关键节大小：

| 节 | 大小 | 说明 |
|---|---|---|
| `.text` | `0x3277C`（206,716 B） | 代码，占全库 56% |
| `.rodata` | `0x7291`（29,329 B） | 只读数据 |
| `.rela.dyn` | `0xD6C8`（54,984 B） | 重定位，密度偏高 |
| `.data.rel.ro` | `0x4C08` | 19,464 B |
| `.bss` | `0x548` | |

依赖极简（观测）：`liblog.so`、`libz.so`、`libc.so`、`libm.so`、`libdl.so`。

导入表里 **没有任何网络系统调用**（`socket`/`connect`/`send`/`recv`/`getaddrinfo` 全为 0），说明它不是自己做 HTTP 的；但它导入了 `deflate`/`deflateEnd`/`deflateInit2_`/`inflate`/`inflateEnd`/`inflateInit2_`（zlib），即**上报体的压缩在 so 里完成**（推断，证据强）。

其他值得记的导入：`openlog`/`syslog`/`closelog`（走 logd 而非 Java 日志，所以 logcat 里看不到它的输出）、`pthread_create`、`dl_iterate_phdr`、`__stack_chk_fail`、`__memcpy_chk`/`__strncat_chk`/`__vsnprintf_chk` 一组 FORTIFY 符号、`android_set_abort_message`。

`.comment` 段里混进了百度内部构建串（观测）：

```
clang version 11.0.0 (scorpio-server-7.1.0 5928676ee3d71b84711d28a1fc6b9c39b5951d9f)
GCC: (GNU) 4.9.x 20150123 (prerelease)
Android (7155654, based on r399163b1) clang version 11.0.5
Linker: LLD 11.0.5
```

`scorpio-server-7.1.0` 是百度自有编译集群标识，可作为归属旁证。

### 12.1.2 导出面（观测）

定义并导出 109 个 `FUNC`，其中 `Java_` 前缀 18 个，分三组：

- `Java_com_baidu_location_Jni_*`：`a`、`b`、`c`、`ee`、`encodeNotLimit`、`encrypt`、`gsr`、`ldkaiv`、`murmur`（9 个）
- `Java_com_baidu_serverLoc_Jni_*`：`a`、`b`、`c`、`ee`、`encodeNotLimit`、`encrypt`、`gsr`、`murmur`（8 个，比上面少一个 `ldkaiv`）
- `Java_com_baidu_location_fused_sdk_Jni_b`（1 个）

`Java_com_baidu_location_Jni_*` 这 9 个与 `com.baidu.location.Jni` 的声明一一对应，无多余入口（观测）；`serverLoc` 那组是给 `com.baidu.serverLoc` 包用的旧命名空间，本样本 Java 侧未出现同名类，属 SDK 内部冗余导出。各函数体积：`b` 1268 B 最大，`encrypt` 644 B，`encodeNotLimit` 624 B，`c` 600 B，`ee` 596 B，`murmur` 576 B，`gsr` 544 B，`a` 520 B，`ldkaiv` 368 B。

### 12.1.3 字符串混淆原语（观测 + 已复现）

`.text` 内偏移 `0x2453C` 处有一个 7 参的字符串还原函数，被调用 7 次。逻辑（反汇编直读）：

```
if (dst[len+1] == 0x7F) return;                  // 已还原过，幂等跳过
key = len & 0xFF;
for (i = 0; i < len; i++)
    dst[i] = src[i] ^ ((key + i) & 0xFF);        // 即 src[i] ^ ((len + i) & 0xFF)
dst[len+1] = 0x7F;                               // 打哨兵
```

也就是一个 **以字符串自身长度为密钥的循环异或**，加密强度为零：拿到 so 的任何人都能一条命令全量还原。哨兵 `0x7F` 只解决重复调用问题，不构成保护。

全库共 7 处调用（`.asm` 计数）；Hex-Rays 直接输出 4 处，另 3 处在 `sub_246FC` 里被内联未显式出现，回查 `.asm` 补齐。合起来共 6 个不同源。逐一还原的结果（观测，已复现）：

| 所属函数 | 源地址 | 长度 | 明文 | 用途 |
|---|---|---|---|---|
| `Java_com_baidu_location_Jni_ldkaiv` | `0x142B0` | 34 | `qsHcaEWjX0j1dGmZ\|1122334455667788` | AES 密钥与 IV |
| `sub_232E4` | `0x142B8` | 8 | 非文本 8 字节二进制常量 | 未定名 |
| `sub_246FC` | `0x145B4` | 5 | `%02X` | 十六进制格式化 |
| `sub_28EF4` | `0x14B64` | 6 | `1.2.8` | 协议版本串 |
| `sub_28EF4` | `0x14B6C` | 7 | `webgis` | 加密体填充标记 |
| `sub_28EF4` | `0x14B80` | 37 | `webgiswebgiswebgiswebgiswebgiswebgis` | 同上（重复 6 次） |

注意最后两个同属 `sub_28EF4`、源地址相邻（`0x14B6C` 与 `0x14B80`），中间夹着 `0x14B64` 的 `1.2.8`——三个短串挤在同一片 `.rodata`，说明它们是同一套协议常量。`sub_246FC` 那 3 处调用在 Hex-Rays 输出里被内联掉了（只在 `.asm` 可见），这也是「汇编与反编译必须互查」的直接理由。

其中 `webgis` 那两处是**加密填充标记**，不是密钥。反编译出的用法（`Jni` 内部某加密函数）：

```c
// 输入数据末尾追加 7 字节 "webgis"
sub_2453C((__int64)&qword_14AE0[17] + 4, 7, (__int64)qword_5B6A0);
__memcpy_chk(v10 + a3, qword_5B6A0, 7, -1);

// 再在头部拼 3 个 rand() 派生字节 + "webgis" 重复串
LOBYTE(v16[0])  = rand() + rand()/255 + 1;
BYTE1(v16[0])   = rand() + rand()/255 + 1;
WORD1(v16[0])   = rand() + rand()/255 + 1;
sub_2453C((__int64)"RCEO@Y\\IOIFCFWQS\\E@][]ROJ[]'(14!'!.;I", 37, (__int64)qword_5B6B0);
__strncat_chk(v16, qword_5B6B0, 40, 100);
```

`"RCEO@Y\\IOIFCFWQS\\E@][]ROJ[]'(14!'!.;I"` 这个 37 字节的字面量在 `.rodata` 偏移 `0x14B80`，异或还原后就是 `webgis` 重复 6 次。把它当作「加密字段的魔数标记」使用，作用是让服务端能识别包头；顺带把 `rand()` 派生的 3 字节塞进头部做一次性变量。

这个标记有取证价值：**百度定位 SDK 发给 `loc.map.baidu.com` 的加密体，解密后的明文必然含 `webgis` 特征**。抓到密文时可用它判断是不是同一套 SDK。

### 12.1.4 `ldkaiv` 泄漏全设备共用的 AES 密钥（观测，重大）

`Java_com_baidu_location_Jni_ldkaiv`（`0x21E00`，368 B）唯一做的事是调用上面的还原原语：

```
adrp x8, 0x14000 ; add x8, x8, #0x2B0   → src  = 0x142B0（.rodata）
adrp x9, 0x5B000 ; add x9, x9, #0x660   → dst  = 0x5B660（.bss）
mov  w1, #0x22                          → len  = 34
bl   0x2453C                            → 还原
```

`0x142B0` 处那 34 字节解密结果为：

```
qsHcaEWjX0j1dGmZ|1122334455667788
```

以 `|` 切分后正好是 **16 字节 AES 密钥 + 16 字节 IV**。这与 Java 侧 `a.a.a.b.n` 的用法严丝合缝（观测）：

```java
String[] p = Jni.a().split("\\|");                       // 取 ldkaiv 返回值
SecretKeySpec k  = new SecretKeySpec(p[0].getBytes("UTF-8"), "AES");
IvParameterSpec v = new IvParameterSpec(p[1].getBytes("UTF-8"));
Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
c.init(Cipher.DECRYPT_MODE, k, v);                       // 解服务端下发的 enc 字段
```

调用链（观测）：`a.a.a.b.l` / `a.a.a.b.h` / `a.a.a.b.m` / `a.a.a.d.i` 四处都有同一模式——

```java
if (resp.contains("enc") && n.b().a())
    str = n.b().a(new JSONObject(resp).getString("enc"));  // 解密
```

结论（推断，证据强）：百度定位 SDK 的**服务端下行加密密钥是全局硬编码的**，不随设备、不随 AK、不随会话变化。任何人从任意一个装了该版本百度定位 SDK 的 APK 里提取 `liblocSDK8b.so`，就能解密所有设备收到的 `enc` 下行包。它保护的是「链路被动抓包的旁观者」，防不住「拿到 APK 的分析者」。

`ldkaiv` 自身还带一段运行时自检。**Hex-Rays 全量反编译**（见 12.4）给出的精确形态（观测）：

```c
__int64 __fastcall Java_com_baidu_location_Jni_ldkaiv(__int64 a1, __int64 a2)
{
  savedregs_8 = *(_QWORD *)(_ReadStatusReg(TPIDR_EL0) + 40);
  if ( (unsigned int)(-1717986918 * a_fda_iee + 1288490188) >= 0x33333333
    && (14 * a_fda_iee * a_fda_iee - 19 * a_fda_iee - 19) % 25 == 0
    || (sub_2453C((__int64)qword_142B0, 34, (__int64)qword_5B660),   // 还原 key|iv
        v3 = ((__int64 (__fastcall *)(__int64, __int64 *))loc_21CA0)(a1, qword_5B660),
        ~(mva454jiw * mva454jiw) + 8 * mva454jiw * mva454jiw == a_fda_iee * a_fda_iee) )
  {
    JUMPOUT(0x21F64);          // 直接返回, v3 未初始化
  }
  return v3;
}
```

三点关键事实：

1. 自检变量是 `a_fda_iee` 与 `mva454jiw`（两个 `.bss` 全局 int，`.data` 侧还有 `qword_5B660` 作输出缓冲）。
2. 还原调用 `sub_2453C(qword_142B0, 34, qword_5B660)` 的参数 `34` 与前面 `ldkaiv` 里的 `w1 = 0x22` 完全对上，**反编译侧独立确认了长度 34**。
3. 逻辑结构是 `(A && B) || (C && D)`，任一为真就 `JUMPOUT(0x21F64)` 返回**未初始化的 `v3`**。也就是说这不是「校验失败就拒绝」，而是「条件成立就返回垃圾值」。

自检的两个式子化简后都是「某个乘积关系是否成立」：`-1717986918·x + 1288490188 ≥ 0x33333333` 是 `x ≤ 0` 的变体（`-1717986918 = -0x66666666`），`(14x² − 19x − 19) % 25 == 0` 与 `7y² − 1 == x²` 是同一族二次剩余判断。语义未做实机动态验证，标**推断**：属 SDK 自身状态校验或失效判断，不是针对分析者的反调试。

需要说明一处反编译伪影：`loc_21CA0` 本应是 `Java_com_baidu_location_Jni_encodeNotLimit` 的函数入口，但 IDA 把它认成了标号（同一段代码被两个导出符号共用）。这是 `-Ohexrays:ALL` 模式下部分函数体缺失的典型原因，也是本次改用函数级全量反编译的直接动因（12.4）。

### 12.1.5 其余 JNI 语义（观测）

Java 侧 `Jni` 类的包装给出了直接语义：

| JNI | Java 包装 | 用途 |
|---|---|---|
| `gsr(f, d, d)` | `a(float, double, double)` | 坐标换算，返回 double |
| `b(d, d, int, int)` | `b(double, double, int, int)` | 坐标系转换，返回 `"经度:纬度"` |
| `murmur(str)` | `d(String)` | murmur 哈希，用于 WiFi BSSID / 历史数据主键 |
| `c(byte[], int)` | `c(String)` | 短串加密，用于 `BSSID.replace(":","")` 后做 key |
| `a(byte[], int)` | `a(String)` | 加密，输出带 `|tp=3` 后缀 |
| `encodeNotLimit` | `e(String)` | 不限长加密，输出带 `|tp=3` |
| `ee(str, int)` | `f(String)` | 加密（另一路径），无后缀 |
| `encrypt` | — | 底层加密实现，Java 侧不直接调 |
| `ldkaiv` | `a()` | 返回 `key|iv`（见上） |

除 `ldkaiv` 外，其余函数的上行加密算法（自定义异或/置换还是标准 AES）未做完整还原，标**未知**；但本次全量反编译（12.4）已给出各函数的调用骨架，可确认它们是「拼包头 → 逐块变换 → 追加 `webgis` 填充」的同族实现，见 12.1.3 那张表的用法片段。可以确定的是：**两个 so 里都不存在标准 AES S-box、也不存在 MD5 的 64 个常量字**（`liblocSDK8b.so` 与 `libindoor.so` 均全文搜索无命中，观测），也说明联通 DM 报文的 MD5/AES/RSA 完全在 Java 层（`c.d.a.b.c`）实现，与原生库无关。

### 12.1.6 与联通链路的边界（观测）

`liblocSDK8b.so` 的 18 个 JNI 全部挂在 `com.baidu.location.Jni` / `com.baidu.serverLoc.Jni`，与 `com.mobiletools.systemhelper.*` 无任何符号级关联；`com.mobiletools.systemhelper` 包内也不调用除 `com.baidu.location.Jni` 之外的原生方法。因此它只参与百度定位 SDK 自身的数据链路，不进联通 DM 报文（推断，证据强）。

## 12.2 `libindoor.so`：一个注定加载失败的室内定位库

### 12.2.1 结构（观测）

25 个节，主要分布：

| 节 | 大小 |
|---|---|
| `.text` | `0xF8524`（1,017,636 B，占 64%） |
| `.rodata` | `0x9D45`（40,261 B） |
| `.eh_frame` | `0x1B440` |
| `.gcc_except_table` | `0xAEA4` |
| `.dynstr` | `0x1A936` |
| `.bss` | `0x3588` |

定义并导出 1439 个 `FUNC`（含大量 C++ 与 libc++abi 符号），未定义导入 210 个。光 `.dynstr` 就 108,854 B，符号表规模本身就说明这是整包打入的重型库。

从字符串面看，它把整套 GNSS 后处理都链了进来：RINEX 2/3 表头（`RINEX VERSION / TYPE`、`ION ALPHA`、`TIME SYSTEM CORR`、`LEAP SECONDS`、`WIDELANE SATELLITE FRACTIONAL BIASES`）、卫星观测码（`1C`/`2L`/`5Q`/`8X` 等约 70 个）、多系统码（`GPSA`/`GAL`/`QZSA`/`BDSA`/`IRNA`/`GLUT`）、矩阵运算错误输出，再叠加 `mml_framework` 的神经网络推理接口。而 Java 侧实际只声明 16 个、能对上 13 个入口（见 12.2.3）。

### 12.2.2 依赖缺失，加载必然失败（观测，关键）

`DT_NEEDED` 列了 7 项（观测）：

```
libz.so  liblog.so  libapp_BaiduVIlib.so  libmml_framework.so  libm.so  libdl.so  libc.so
```

其中 **`libapp_BaiduVIlib.so` 与 `libmml_framework.so` 既不在 APK 的 `lib/arm64-v8a/` 里，也不在实机 `/system/lib64/`、`/vendor/lib64/` 里**（两侧实测均 `No such file or directory`，观测）。

`libindoor.so` 还从这两个库导入了具体符号（观测）：

- `mml_framework::MMLMachineService::{load,run,release,getInputData,getOutputData}` —— 神经网络推理框架
- `mml_framework::MMLTensor::{Resize,data<float>,mutable_data<float>,shape}` —— 张量
- `_baidu_vi::{CVDatabase,CVStatement,CVResultSet,CVString}` 一组 —— 百度自研的嵌入式数据库（看命名是 SQLite 的封装）

这些符号无库可解析，`dlopen` 阶段就会失败。

加载处的异常处理（观测，`IndoorJni` 静态块）：

```java
try { System.loadLibrary("indoor"); f1379a = true;
      System.err.println("load vdr indoor lib success."); }
catch (Throwable th) { Log.i("indoorJNI", "indoor lib annot load indoor lib:" + th);
      th.printStackTrace(); f1379a = false; }
```

`catch (Throwable)` 吞掉了 `UnsatisfiedLinkError`，所以**不会崩溃，只是静默降级**。

调用方（观测，`a.a.a.b.e`）全部先查 `IndoorJni.f1379a`，为 false 时直接返回哨兵值：`a(String)` 返回 `-1`，`a(String,String)` 返回 `-100`/`-101`。所以室内定位/惯导/楼层识别在本样本中**完全不工作**（推断，证据极强）。

### 12.2.3 Java 声明与 so 导出不匹配（观测）

`IndoorJni` 只声明 16 个 native，而 so 导出 134 个 `Java_com_baidu_location_indoor_mapversion_IndoorJni_*`：

| 分类 | 数量 |
|---|---|
| Java 声明 | 16 |
| so 导出 | 134 |
| 交集 | 13 |
| **Java 有、so 无** | 3：`destroyGpsChecker`、`getGpsStatus`、`initGpsChecker` |
| so 有、Java 无 | 121（`initOfflineLoc`、`getSubwayStatus`、`getVdrNaviRes`、`initPaddleSpeedPredict` 等） |

这是**双向版本错配**：Java 侧是精简过的旧封装，so 是功能完整的另一版本。即使补上依赖库，那 3 个被 Java 声明的方法也会在调用瞬间抛 `UnsatisfiedLinkError`——但因为 `f1379a=false` 前置拦截，实际走不到（观测）。

### 12.2.4 内含 `ptrace` 反调试（观测）

so 导入了 `ptrace@LIBC`，在 `.text` 里有 4 处调用，全部是同一形态：

```
mov w0, #0    ; PTRACE_TRACEME
mov w1, #0    ; pid = 0
mov w2, #0    ; addr = 0
mov w3, #0    ; data = 0
bl  ptrace@plt
```

调用点：`0xDCE9C`、`0xDDE80`、`0xDE4D8`、`0xE0C04`。这是标准的「自跟踪」反调试——若父进程已是调试器，`PTRACE_TRACEME` 会失败。

但四处**返回值都没有被检查**（观测）：`0xDCE9C` 之后直接 `b 0xDD2CC`，`0xDDE80` 之后 `b 0xDDC6C`，`0xDE4D8` 之后 `b 0xDE480`，`0xE0C04` 之后恢复寄存器直接 `ret`。全是无条件继续，没有 `cbnz`/`cmp`/`tbnz` 一类分支。也就是说它只是「做了但没用」——不改变控制流，起不到反调试效果（推断，证据强）。

需要说明：这四个地址都落在符号 `xkjgaol` 的覆盖范围内。该符号是 `WEAK`、大小仅 24 B、地址 `0xA7A8C`，本体只是个 thunk（`bl` 两次跳转）。由于库被 strip，符号表无法还原真实函数边界，"`xkjgaol+0x35C4C`" 这类偏移并不能说明调用者身份，只能定位地址。库内还存在极简的字符串解密函数（`0xA7AC8`），形态与 `liblocSDK8b` 的同名原语一致（`out[i] = src[i] ^ ((len+i) & 0xFF)`，`0x7F` 哨兵）。

### 12.2.5 内含 `system()`，但不可达（观测）

so 导入 `system@LIBC`，2 处调用，参数由 `sprintf` 生成。格式串同样是加密存储的，按上面那套异或还原后得到（已复现）：

| .rodata 偏移 | 长度 | 明文 |
|---|---|---|
| `0x148350` | 26 | `gzip -f -d -c "%s" > "%s"` |
| `0x148380` | 21 | `tar -C "%s" -xf "%s"` |

用途很明确：解压 GNSS 星历/RINEX 数据包。同一片 `.rodata` 里紧接着就是 `RINEX VERSION / TYPE`、`ION ALPHA`、`ION BETA`、`TIME SYSTEM CORR`、`LEAP SECONDS`、`WIDELANE SATELLITE FRACTIONAL BIASES` 等 RINEX 2/3 表头，以及 `.gz`/`.Z`/`.z`/`.zip`/`.ZIP`/`.tar`/`.GZ` 一组扩展名判断，还有 `G%02d`/`R%02d`/`E%02d`/`C%02d` 卫星编号格式串与 `1C`/`1W`/`2L`/`5Q` 一类观测码（`%s` 位置是文件路径，来自内部下载的星历文件，不是外部输入）。

所以：它确实是**用 `system()` 执行 shell 命令**，但（1）参数是文件路径而非网络可控内容，（2）该 so 因依赖缺失根本加载不起来。**在本样本中不可达**（推断，证据极强）。

### 12.2.6 全量字符串还原结果（观测）

同一还原原语在 `libindoor.so` 里被调用 233 次，脚本按「`adrp`+`add` 取源地址、`mov w1` 取长度」的模式全量抽取，成功解出 228 条去重前条目。内容分布：

- GNSS/RINEX 相关：约 150 条（表头、观测码、卫星系统码 `GPSA`/`GAL`/`QZSA`/`BDSA`/`IRNA` 等、`az=%f , el=%f` 调试输出、`matrix memory allocation error`）
- 解压命令：2 条（上表）
- 扩展名与格式串：约 70 条（`.gz`/`.tar`/`%lf`/`%03d`/`%c%d` 等）

**没有域名、没有 URL、没有 C2 地址、没有密钥、没有 Token**（观测）。这一点与 `liblocSDK8b.so` 一致：两个 so 都不做网络。

### 12.2.7 死代码判定（观测 + 推断）

`libindoor.so` 相关的全部 Java 侧路径已核对：

| 项 | 事实 |
|---|---|
| 声明方 | `com.baidu.location.indoor.mapversion.IndoorJni` |
| 调用方 | `a.a.a.b.e`（唯一），经 `f1379a` 门控 |
| 上游 | 百度 SDK 内部室内定位分支 |
| 联通 DM 侧是否碰它 | 否，`com.mobiletools.systemhelper` 全包无引用 |
| 实机 logcat 有无 `indoorJNI` 记录 | 无（观测，未捕获到） |

结论（推断，证据极强）：`libindoor.so` 在本样本中是**死代码 / 无效载荷**——体积 1.6 MB 占了全包一半，实际永远不加载。它的存在只说明打包时没有清理百度 SDK 的室内定位组件及其依赖，「精简」不彻底。

需要注意一个容易混淆的点：**百度 SDK 的 WiFi SSID 上报（`daup.map.baidu.com/cltr/rcvr`）不依赖 `libindoor.so`**，那条链路走的是 `a.a.a.c.f` + Java 层加密，与室内定位库无关，仍然是活的（见第十五章 15.1.2）。

## 12.3 两个 so 的共性结论

- **都不做网络**：`liblocSDK8b.so` 零网络系统调用，`libindoor.so` 无 `socket` 系导入，只有 `system`/`open`/`fopen`/`mmap` 一类文件与进程函数。两库的 HTTP 全在 Java 层（`a.a.a.b.j`/`y`/`l`/`c.a.c.a` 等）。
- **都不实现 DM 报文的加解密**：无 AES S-box、无 MD5 常量表。DM 的 `MD5 → AES/ECB` + `RSA/PKCS1` 全在 `c.d.a.b.c`（Java）。
- **都用同一套弱字符串混淆**：以长度作 XOR 密钥 + `0x7F` 哨兵，可全量批量还原。
- **都没有有效的反分析手段**：无 `ptrace` 有效检查（`libindoor` 有调用但丢返回值）、无 `frida`/`xposed` 探测、无完整性自校验（`liblocSDK8b` 的自检只针对自身全局状态）。

唯一的实质安全问题是 `ldkaiv` 硬编码 AES 密钥（12.1.4），它影响的是百度 SDK 的下行链路，不影响联通 DM 报文。

两项「看起来严重、实际不成立」的观察需要明确区分，避免误报（下表）：

| 观察 | 严重性判断 | 依据 |
|---|---|---|
| `libindoor.so` 调 `system("gzip …")` / `system("tar …")` | 不成立 | so 依赖两个不存在的库，永不加载（12.2.2） |
| `libindoor.so` 调 `ptrace(PTRACE_TRACEME)` 4 处 | 不成立 | 返回值不检查，不改变控制流（12.2.4）；且 so 不加载 |
| 百度 SDK 上报已保存 WiFi SSID | **成立** | 走 Java 层，与 so 无关，实测逻辑闭合（15.1.2） |
| 百度 SDK 下行 AES 密钥硬编码 | **成立** | `ldkaiv` 明文返回 `key|iv`（12.1.4） |

## 12.4 全量反编译（IDA 9.4 + Hex-Rays，已落地）

为把静态推断钉到指令级，两个库都在远端 IDA Pro 9.4（x86_64，128 核 / 1 TB 内存的计算节点）上做了完整反编译。产物已归档到本地 `work/systemhelper/ida/`。

### 12.4.1 方法与一个必须绕开的坑（观测）

第一轮直接用 `idat94 -A -Ohexrays:<out>:ALL`，结果**漏函数**：`liblocSDK8b.so` 只输出 853 个函数体，而 IDA 实际识别 1383 个。日志里没有任何报错，只是「没尝试」。

原因是 IDA 的自动分析把若干导出符号当成了**标号**而非函数入口。典型例子是 `0x21E00`（`Jni_ldkaiv`）：它的 `is_code` 为 True、名字也对，但 `get_func()` 返回 `None`——即这段代码没有函数对象包裹，Hex-Rays 自然跳过。同一现象还波及 `Jni_encodeNotLimit`、`Jni_ee`、`Jni_encrypt`、`Jni_a`（location 与 serverLoc 两套）。

更隐蔽的是：`loc_21CA0` 与 `Java_com_baidu_location_Jni_encodeNotLimit` 指向同一段代码（`0x21CA0` 是函数体，`0x21A30` 是导出入口，中间隔了一层跳转）。IDA 把前者当标号、后者当非函数，两边都没建成函数，于是整段代码在 `ALL` 模式下完全消失。

解决办法是自己写 IDAPython 脚本（`ida/jnitool.py`），流程是：

1. 遍历 ELF 导出表，筛出可执行段内的入口
2. 对每个入口查 `get_func()`，若返回 `None` 或起点不符，则用**下一个导出入口的地址**作上界，调 `add_func(ea, end_hint)` 强制补建
3. 补建完成后按 `get_func_ea_by_num` 逐个 `decompile()`，把函数名与地址作为注释写进输出

这个办法把 `liblocSDK8b.so` 的 18 个 JNI 修好了 17 个（唯一失败的 `serverLoc_Jni_encrypt` 位于库尾，没有下一个导出可作上界）。

### 12.4.2 覆盖率（观测）

| 库 | IDA 函数数 | 反编译成功 | 失败 | 输出行数 | 输出大小 |
|---|---|---|---|---|---|
| `liblocSDK8b.so` | 1383 | 1324 | 59 | 45,747 | 984 KB |
| `libindoor.so` | 3872 | 3662 | 210 | 218,851 | 5.2 MB |

失败项全部是**无函数体的外部导入**，属预期，不是反编译缺陷：

- `liblocSDK8b.so` 的 59 个：`__cxa_*`、`__memcpy_chk`、`deflate*`、`inflate*`、`malloc`、`free`、`rand` 等 PLT 桩；另有 2 处真实失败 `sub_30C20`、`sub_31CC4`（`call analysis failed`）
- `libindoor.so` 的 210 个：207 个是 `mml_framework::*` 与 `_baidu_vi::*` 等 UND 符号（正好印证 12.2.2 的依赖缺失），另 3 个是 `start`、`sub_5A018`、`sub_AFBF4`

### 12.4.3 反编译对既有结论的验证（观测）

全量反编译独立复核了此前所有靠汇编得出的判断，无一被推翻：

| 此前结论 | 反编译证据 |
|---|---|
| `ldkaiv` 还原长度 34 的 `key|iv` | `sub_2453C((__int64)qword_142B0, 34, (__int64)qword_5B660)` |
| `libindoor` 有 4 处 `PTRACE_TRACEME` | `ptrace(PTRACE_TRACEME, 0, 0, 0)` 出现 4 次（行 128493/128698/128886/130833） |
| `libindoor` 用 `system()` 跑解压命令 | `sub_AD420`：`sub_A7AC8(qword_148350, 26, qword_1877F0); sprintf(...); system(...)` |
| `libindoor` 缺 3 个 Java 声明的方法 | 反编译产物里 `destroyGpsChecker`/`getGpsStatus`/`initGpsChecker` **零出现**，其余 13 个各 1 次 |
| `libindoor` 依赖 `mml_framework` 与 `_baidu_vi` | 210 个反编译失败项里 207 个正是这两组符号 |

`libindoor` 里 `system()` 那处的完整反编译形态（`sub_AD420`）：

```c
void sub_AD420()
{
  char *v0; // x19
  __int64 v1; // x20
  strcpy(v0, (const char *)&STACK[0x440]);
  v0[v1 - (_QWORD)&STACK[0x440]] = 0;
  sub_A7AC8((__int64)qword_148350, 26, (__int64)qword_1877F0);   // 还原格式串
  sprintf((char *)&STACK[0x840], (const char *)qword_1877F0, &STACK[0x440], v0);
  system((const char *)&STACK[0x840]);
  JUMPOUT(0xAD2DC);
}
```

`qword_148350` 正是 12.2.5 里那张表的第一行（`gzip -f -d -c "%s" > "%s"`），长度 26 也对上。三个参数 `&STACK[0x440]`、`v0` 都是内部路径缓冲，与「网络可控输入」无关的判断成立。

另有一个值得记的实现细节：`sub_AD420` 结尾是 `JUMPOUT(0xAD2DC)` 而非 `ret`。这是百度在 so 里做的**控制流扁平化**——大量函数尾部跳到同一个分发器，用 `x8` 寄存器做 `BR X8` 间接跳转（`sub_AD2F8` 就是这么被 `BR` 命中的）。这解释了为什么反编译产物里会看到 `__asm { BR X8 }` 与成片的 `JUMPOUT`：属百度自身的混淆，不是 IDA 的缺陷。

### 12.4.4 产物质量与读法（观测）

全量 dump 是**完整的**，但可读性受百度自身的混淆限制，需如实说明：

- **控制流扁平化**：大量函数尾部是 `JUMPOUT(0xXXXX)` 而不是 `ret`，配合 `__asm { BR X8 }` 间接跳转，形成「所有分支汇到一个分发器」的结构。`sub_AD420`（解压命令）、`sub_22F98`（`Jni_b` 尾部）都是这个样子。
- **寄存器复用导致的伪变量**：`savedregsb`/`savedregsc`/`savedregs` 共享同一栈槽，Hex-Rays 只能给出 `savedregsb`/`savedregsc`/`savedregs` 这种名字，看不出真实语义。
- **跨函数跳转**：`loc_2265C`、`loc_2A238`、`loc_23FF8`、`loc_2411C` 这类「函数体被当成标号」的情况大量存在（与 12.4.1 同一根因），表现为 `((__int64 (__fastcall *)(...))loc_XXXX)(...)` 的强制转换调用。

因此读法建议：**函数边界与调用关系以 `.full.c` 为准，具体算法细节回查 `.asm`**。`.asm` 保留了 IDA 的 XREF 注释与符号表，两者配合使用才可靠。本报告第 12.1 至 12.2 节的所有结论都做了这层交叉核对。

另需说明一处 Hex-Rays 的已知误读：`Jni_encrypt` 里出现了 `__strlen_chk((const char *)0xFFFFFFFFFFFFFFFFLL, ...)`，这明显是把寄存器初值当成了实参，属反编译伪影，不是真实调用。此类伪影在扁平化代码里较常见，不影响整体结论。

### 12.4.5 产物清单

| 路径 | 内容 |
|---|---|
| `ida/liblocSDK8b/hexrays/liblocSDK8b.full.c` | 1383 个函数块，45,747 行 |
| `ida/liblocSDK8b/asm/liblocSDK8b.asm` | IDA 汇编清单（含 XREF 与符号表） |
| `ida/liblocSDK8b/log/{build,hexrays,jni}.log` | 建库、首轮反编译、修复补建的过程日志 |
| `ida/libindoor/hexrays/libindoor.full.c` | 3872 个函数块，218,851 行 |
| `ida/libindoor/asm/libindoor.asm` | 同上，21 MB |
| `ida/libindoor/log/{build,hexrays,jni}.log` | 同上 |
| `ida/jnitool.py` | 修函数边界 + 函数级全量反编译脚本（可复用于任何 stripped so） |

远端原始数据库（`.i64`）留在服务器 `~/0/dataida/<lib>/db/`，本地因空间只保留文本产物（4.2 GB 可用）。

# 十三、本地存储与历史补传

两个独立 SQLite 库（观测）：

| 库 | 表 | 结构 | 上限 | 用途 |
|---|---|---|---|---|
| `systemhelper` | `dmregister` | `ID INTEGER PK AUTOINCREMENT, jsonString TEXT` | 10 条 | 常规待补传 |
| `systemhelper` | `typef` | 同上 | 10 条 | 首次开机（`F`）专用 |
| `signalhelper` | `signal` | 同上 | 100 条 | 信号采样 |

`SharedPreferences`：`com_mobiletools_systemhelper_preference`（`MODE_MULTI_PROCESS=4`），键有 `serverAddress`、`scheduleInterval`、`appInfoInterval`、`signalInfoInterval`、`iccid1`、`iccid2`、`firstPowerOn`、`preference_enable_log`。

补传（观测，`control.d`）：每次成功上报后立刻启动 `HistoryPostThread`，先取 `typef` 一条、再取 `dmregister` 一条；**每次只各取一条**，不做循环排空。也就是说积压 10 条要 10 次成功上报才能清完。

取记录用的是 `moveToLast()`（取最新）而不是 `moveToFirst()`，但日志文案写的是 `queryOldestRecord`（观测，文案与实现不符）。删除时 `new String[]{cursor.getString(columnIndex("ID"))}` 取的是 `ID` 列，逻辑正确。

容量控制有 bug：`if (count >= 10) { moveToFirst(); delete("ID=?", new String[]{String.valueOf(cursor.getColumnIndex("ID"))}) }`，删除条件用的是**列索引**（恒为 0 或 1）而不是列值，导致实际删除的是 `ID=0` 或 `ID=1` 的行，长期运行会删错行甚至删不掉（观测，三处同样写法：`f.a/f.b`、`n.a`）。

`RegisterHelperService` 事务码 3 会直接删 `shared_prefs/...xml`（`m.a()`），即远程擦除本地状态。

# 十四、与联通 DM 平台的交互面

## 14.1 端点（观测）

| URL | 方法 | 用途 |
|---|---|---|
| `http://dm.wo.com.cn:18080/register` | POST | 主上报 |
| `http://dm.wo.com.cn:18080/public/ip` | GET | 取出口 IPv4 |

`serverAddress` 可被 `SharedPreferences` 覆盖，`e.f1333b`（调试开关）为真时强制用默认值。`e.f1333b` 同样**全工程无赋值**，恒 false，所以覆盖始终生效。

`public/ip` 的响应处理：3s 连接 / 3s 读超时，支持 gzip（看 `Content-Encoding`），把整个响应体 `trim()` 后当 IP 用——没有校验、没有 JSON 解析，服务器返回什么就原样塞进 `IPv4`（观测）。不过该线程当前恒不执行（见第六章）。

## 14.2 现网探测（观测）

```
GET  http://dm.wo.com.cn:18080/public/ip  → 403 Forbidden
POST http://dm.wo.com.cn:18080/register   → 403 Forbidden
Date: Tue, 10 Nov 2026 14:02:42 GMT
WZWS-RAY: 1249-1794348162.289-w-waf08zzst
eventID: ... reason:UrlACL
Client IP: 182.104.93.33
```

`WZWS-RAY` 是网宿（WangSu）WAF 的指纹头，`reason:UrlACL` 表示按 URL 命中了访问控制。两个路径都被拦，说明拦截粒度是**路径级**而非 IP 级，或该端口已整体下线只留 WAF 兜底（推断）。

因此以下问题只能标「未知」：

- 服务端是否仍在校验 `sign`、是否做时间窗防重放
- 响应体是什么（是否含下发配置/指令）
- `416` 这个「当成功处理」的状态码原本代表什么业务语义

## 14.3 服务端下发能力（未知）

代码里**没有任何解析响应体的逻辑**：`g.a()` 只对比状态码，`InputStream` 从未被读取（观测）。上报是纯粹的单向上报，没有「下发指令 → 本地执行」的执行链。

这一点很重要：即使服务端想下发配置，这个版本的客户端也不会读、不会执行（观测 + 强推断）。

# 十五、风险与技术观察

## 15.1 数据采集面

单次报文可含（推断，按字段实装情况）：

- 双 IMEI、双 IMSI、双 ICCID（联通卡明文，其他卡 SHA-256）
- 双卡 MNC / TAC / CID / PCI / 网络制式 / VoLTE / 5G / VoNR 状态
- 出口 IP（设计上有，实现上因死分支未启用）
- 全量已安装应用的名称、包名、前台时长、分卡流量、WiFi 流量（每 6h 一次）
- 百度经纬度 + 海拔（`bd09ll`）
- 信号质量矩阵（RSRP/RSRQ/SINR/CSI/CQI，最多 100 条历史采样）
- 硬件/系统版本、内存与存储容量
- （不经联通，经百度 SDK 另行外发）已保存 WiFi 的 SSID 与关联次数，见 15.1.2

按国内《个人信息保护法》口径，IMEI + IMSI + 精确位置 + 应用列表属于敏感个人信息叠加，单独一项都需单独同意。本样本的做法是：**系统预装 + 权限 `GRANTED_BY_DEFAULT` + 用 `Settings` 里的系统级开关当「用户同意」**（观测）。

## 15.1.1 「用户同意」门控在各厂商分支上的实际强度

`e.e` 是全局的 `isUserPermissionOpen`，决定「是否采集应用统计」「是否注册 TelephonyCallback」「是否真的发报文」。各厂商读取器对它的赋值方式差异极大（观测）：

| 分支 | 类 | 判定 | 实际强度 |
|---|---|---|---|
| 基类 | `c.d.a.a.a` | `Settings.Global.device_provisioned == 1` | **只表示「已过开机向导」** |
| 小米 | `c.d.a.a.j` | 同上（`DeviceInfoReaderXiaomi.d()`） | 同上 |
| OPPO | `c.d.a.a.d` | 同上（`DeviceInfoReaderOPPO.d()`） | 同上 |
| vivo | `c.d.a.a.i` | `device_provisioned==1` **且** `Settings.Secure.operator_service_improve_plan==1` | 真有二次开关 |
| ZTE | `c.d.a.a.k` | `Settings.Secure.dm_user_agreement == 1` | 有专用开关 |
| realme | `c.d.a.a.f` | **不赋值**，只读基类已写好的 `e.e` | 继承上游结果 |
| 中兴系 nubia | `c.d.a.a.c` | **不赋值** | 继承上游结果 |
| 联想 `Liantong` | `c.d.a.a.b` | **不赋值** | 继承上游结果 |
| 一加 `OnePlus` | `c.d.a.a.e` | **不赋值** | 继承上游结果 |
| 三星 `SamSung` | `c.d.a.a.g` | **不赋值** | 继承上游结果 |
| 天玑 `TDTECH` | `c.d.a.a.h` | **不赋值** | 继承上游结果 |

也就是说：**只有在 vivo 和 ZTE 上存在真正的「用户同意」语义**；在小米/OPPO 以及走基类兜底的机型上，`e.e` 退化成「手机开过机」，对任何已完成初始化的设备恒为 true（推断，证据强）。另外 6 个分支完全不自判，直接沿用基类写的 `e.e`。

本机是小米机型（已隐去），走 `c.d.a.a.j`，`e.e = (device_provisioned == 1)`，实机必然为 true，所以**采集与上报链路在本机是全开的**，不存在用户未同意导致的不采集。

### 15.1.1.1 分发是怎么选的（观测）

很多人会以为分发看 `Build.MANUFACTURER`，实际不是。`c.d.a.a.l.c()` 先把 `ro.product.manufacturer` 读出来，**只有命中 9 个白名单值**才把 `Build.MODEL → manufacturer` 写进 `Map f1325a`：

```java
String m = m.a("ro.product.manufacturer");
if (m.trim().equalsIgnoreCase("vivo") || m.trim().equalsIgnoreCase("samsung")
 || m.trim().equalsIgnoreCase("realme") || m.trim().equalsIgnoreCase("Xiaomi")
 || m.trim().equalsIgnoreCase("OPPO") || m.trim().equalsIgnoreCase("Liantong")
 || m.trim().equalsIgnoreCase("OnePlus") || m.trim().equalsIgnoreCase("TDTECH")
 || m.trim().equalsIgnoreCase("nubia")) {
    f1325a.put(Build.MODEL, m);
}
```

然后 `l.a(Context)` 用 `f1325a.get(Build.MODEL)` 取厂商名，**取不到就落到基类 `c.d.a.a.a`**。因此分发有三个隐含约束：

1. 白名单外的一切厂商（华为、荣耀、魅族、摩托、海信…）一律走基类，读的是最基础的一组属性；
2. `ro.product.manufacturer` 为空时 `c()` 直接 `return`，`f1325a` 是空 Map，同样落基类；
3. `Model` 必须是精确匹配的键，`Map` 里一个型号只对应一个厂商，同型号多厂商代工的情况会串。

九条分支里，只有 5 个真正读了自己特有的属性（下表），其余 4 个（`Liantong`/`OnePlus`/`TDTECH`/`nubia` 的 `c` 分支除外）只是换了 API 版本门槛，字段与基类一致。

### 15.1.1.2 各分支实际读的私有属性（观测）

| 分支 | 读的私有属性 | 写入字段 | 额外模型门控 |
|---|---|---|---|
| 小米 `j` | `ro.miui.cust_hardware`（机型 `2106118C` 例外用 `ro.build.hardware.version`）、`Settings.Global.miui_version_name` 或 `ro.build.version.incremental` | `HWVersion`、`SWVersion` | 无 |
| nubia `c` | `ro.build.display.id`、`ro.product.hardware` | `SWVersion`、`HWVersion` | **只认 `NX659J`/`NX651J`/`angelcare N9`**，其余直接 return |
| OPPO `d` | `ro.build.hardware.version` | `HWVersion` | 无 |
| vivo `i` | `ro.vivo.hardware_version`（空则 `MP_0.1`）、`ro.vivo.op.entry.version` 或 `ro.vivo.product.version`（按 `ro.vivo.op.entry` 是否含 `UNICOM` 二选一） | `HWVersion`、`SWVersion` | 无 |
| 三星 `g` | `ril.sw_ver`、`ril.hw_ver` | `SWVersion`、`HWVersion` | 无 |
| realme `f` | `ro.build.display.id`、`ro.build.hardware.version` | `SWVersion`、`HWVersion` | 无 |
| 联想 `Liantong` `b` / 一加 `e` / 天玑 `h` | 无（只调共用的 `b()`） | — | 无 |

`vivo` 那组值得单独记：`ro.vivo.op.entry` 含 `UNICOM` 时读 **`ro.vivo.op.entry.version`**，否则读 `ro.vivo.product.version`。也就是说**联通定制版与公开版上报的 `SWVersion` 来自不同属性**，这解释了为什么联通能从版本串上区分渠道机（推断）。

### 15.1.1.3 一个确定的实现缺陷：Android 13+ 上 `b()` 被调用两次（观测）

`minSdkVersion=31`、`targetSdkVersion=33`。基类 `a(Context, b)` 的非 vivo 路径是：

```java
if (Build.VERSION.SDK_INT >= 31) {
    b(context, bVar);       // 采卡信息、小区信息
    return;
}
```

而 `Liantong`/`OnePlus`/`TDTECH`（`b`/`e`/`h`）以及 `SamSung`（`g`）在 `super.a()` 之后又自己调了一次：

```java
super.a(context, bVar);
if (Build.VERSION.SDK_INT >= 33) {
    b(context, bVar);       // 第二次
    return;
}
```

`SDK_INT >= 33` 时基类已经调过一次并 `return`，子类回来后**再调一次**。smali 复核确认这四类里各只有 1 处 `invoke-virtual ...->b(...)`，加上基类那次共 2 次。

`b()` 不是纯函数——它会 `registerTelephonyCallback` 之外的采集、写 `bVar` 的 14 个卡字段、并调用 `c(context, subId)`/`a(context, slot, bVar)`。重复执行的后果是同一字段被覆盖两次（幂等性上没有外显错误，但多跑一遍 `ServiceState` 查询与网络注册信息遍历）。标**观测（确定会执行两次）+ 推断（影响限于性能与日志噪声，不改变上报内容）**。

顺带记录一处真实缺陷（观测，`c.d.a.a.a.a(Context, b)`）：

```java
if (bVar.f1410a == "vivo") { ... }   // 字符串用 == 比较
```

`Manuf` 是从 `HashMap` 里取出的 `String`，`==` 比引用而非内容，该分支**几乎永不成立**。后果是 vivo 机型如果没走到自己的 `DeviceInfoReaderVIVO`，会落到基类的 `Build.VERSION.SDK_INT >= 31` 分支，与设计意图不符（推断）。

## 15.1.2 百度侧的第二条上报面（观测，此前遗漏）

除联通 DM 那条主链路，内嵌的百度定位 SDK 自身还有一条独立上报通道，目标 `https://daup.map.baidu.com/cltr/rcvr`（`qt=cltrw`），内容是**本机已保存的全部 WiFi 配置**。这条链路与 `libindoor.so` 无关，是活的（见 12.2.7 末段）。

触发（观测，`a.a.a.b.z$1` 的 `case 4`）：

```java
boolean p = a.a.a.g.f.w().p();        // WiFi 是否已连接
if (a.a.a.i.i.l()) p = false;         // i.l() 直接 return false，等于无过滤
...
a.a.a.c.f.d().a();                    // 采集
```

之后 `sendEmptyMessageDelayed(4, a.a.a.i.i.N)` 自我续期，`N = 10000`（10 秒轮询一次）。

采集内容（观测，`a.a.a.c.f`）：

```java
for (c cVar : a(a.a.a.g.f.w().i())) {          // i() = WifiManager.getConfiguredNetworks()
    JSONObject o = new JSONObject();
    o.put("ssid", cVar.f122a);                 // 网络名，明文
    o.put("num",  cVar.f123b);                 // numAssociation，关联次数
}
```

即 **SSID + 该 SSID 的历史关联次数**，不做哈希、不脱敏。上报前用 `Jni.e(...)` 加密（`|tp=3`），`info` 字段再挂一份设备信息（`Jni.b(...)`），然后落盘缓存在 `wcnf.dat`（Base64 编码的 JSON）。

`wcnf.dat` 的真实路径不是 `getFilesDir()/lldt/`（`lldt` 是 `a.a.a.i.i.c()` 给别处用的目录）。推一遍：`f.f119b = i.h()`，`i.h() = i.a() + "/baidu/tempdata"`，而 `i.a()` 在 `SDK_INT > 28` 时返回 `getExternalFilesDir(Environment.DIRECTORY_MOVIES)`，所以实际落在：

```
/sdcard/Android/data/com.mobiletools.systemhelper/files/Movies/baidu/tempdata/wcnf.dat
```

这是**外置存储上的应用私有目录**，走 MediaProvider/FUSE 映射，`adb shell` 与 `run-as` 之外的工具在未 root 时通常也读得到（推断）。对取证有意义：这个缓存不需要任何存储权限就能落到用户可见分区。

上报周期是服务端可控的（观测，`c/f.c()`）：

```java
this.f120c = 24;                                    // 默认 24 小时
if (cfg.has("frq")) this.f120c = cfg.getInt("frq");  // 从上次下发里读
if (!z) this.f120c *= 4;                             // 失败一次翻 4 倍
```

`wcnf.dat` 里缓存的就是上一轮的服务端响应，`cfg.frq` 由它带回来。**也就是说百度 SDK 存在「服务端下发 → 改变客户端行为」的配置通道**（频率可变），但只到参数级，不到代码级（观测，无 `DexClassLoader` 一类加载点）。

`a.a.a.b.b`（`UrlConfigManger`）里还有一个能改写 `a.a.a.i.d` 里各服务端地址的处理函数，但它**不是服务端下发**，而是读本地文件（观测，smali 交叉校验）。调用链只有一条，逐级可查：

```
com.baidu.location.f.onCreate()
  → a.a.a.h.a.a(Context)                      // 百度定位服务的接口实现
    → a.a.a.b.b.a().a(context)                // updateUrl
      → 读 getExternalFilesDir(Movies)/baiduLocDev/loc_local_config
        → a.a.a.b.b.a(String)                 // parseConfig
          → a.a.a.b.b.a(type, owner, url)     // setConfig
```

四处校验结果（观测）：全 smali 中 `url_config` 字面量只出现 1 次（就在 `parseConfig` 里）、三参 `setConfig` 的 `invoke-virtual` 只有 1 处（就在 `parseConfig` 里）、`parseConfig` 的调用点只有 1 处（就在 `updateUrl` 里）、`updateUrl` 的调用点只有 1 处（`a.a.a.h.a`）。因此**不存在「服务端响应驱动 url 改写」的路径**。

改写能力（观测）：

```java
case "vdr_log_update":      a.a.a.i.d.g  = str3; break;   // cltr/rcvr
case "indoor_roadnet":      a.a.a.i.d.d  = str3; break;
case "hdyawupdate":         a.a.a.i.d.h  = str3; break;
case "basement_inout":      a.a.a.i.d.i  = str3; break;
case "indoor_poi_data":     a.a.a.i.d.f  = str3; break;
case "loc":                 a.a.a.i.d.f324b = str3; break;  // sdk.php，主上行
case "cfgs":                a.a.a.i.d.f325c = str3; break;
case "indoor_rects":        a.a.a.i.d.e  = str3; break;
```

前置校验只有三条：`owner` 不含 `default_owner`、`url` 不等于 `default_url`、`url` 必须含 `https`，**没有签名校验**。

这条路径的风险等级与「服务端下发」完全不同：

- 若真是服务端下发，攻击者得先突破 TLS 拿到 `enc` 密钥才能改端点；
- 实际是**读本地文件**，任何能往 `/sdcard/Android/data/com.mobiletools.systemhelper/files/Movies/baiduLocDev/` 写 `loc_local_config` 的主体（同设备上的其他应用若有该目录写权限、adb、文件管理器、恶意 ROM 组件）都能把 `sdk.php`、`cltr/rcvr` 等端点指向任意 HTTPS 地址。

不过要如实标注两点限制：一是文件格式为 `{"url_config":[{"type":..,"owner":..,"url":..}]}`，需自行构造；二是 `contains("https")` 只做子串包含，写成 `https://evil.com/?x=https` 这类形式即可满足（推断）。本机实测该目录不存在（`ls` 报 No such file or directory），说明应用尚未写入过，但**创建它不需要应用配合**。这条标**观测 + 推断（未做写入验证）**，不做动态利用。

对隐私的意义：联通 DM 报文里本来没有「已保存 WiFi 列表」，但同一进程内百度 SDK 会把这份数据发给百度。所以在「这台机器上什么数据出去了」这个问题上，答案是**联通 + 百度两方**，而不是一方。

### 15.1.2.1 被漏掉的另一半：`sdk.php` 带的是扫描热点，不是已保存配置（观测）

上面那条 `cltr/rcvr` 只覆盖「设备记住过的 WiFi」（`getConfiguredNetworks()`）。百度 SDK 还有一条更日常的上行，走 `https://loc.map.baidu.com/sdk.php`，内容不同：

```java
// a.a.a.b.m$c.a()  —— 主定位请求体
String strK = a.a.a.g.f.w().k();        // 见下
if (strK != null) this.f = Jni.f(strK);
this.d.put("bloc", Jni.f(this.j));
this.d.put("up",   this.i);             // y.f()
this.d.put("trtm", 当前毫秒);
```

`g.f.w().k()` 的实现（观测，`a.a.a.g.f`）：

```java
for (ScanResult sr : j().f295a) {
    if (sr != null && sr.level != 0 && sr.BSSID != null) arrayList.add(sr);
}
Collections.sort(arrayList, new d());
// 逐个拼 "BSSID去冒号,SSID"，用 Jni.c(...) 加密后串联
sb.append(sr.BSSID.replace(":", "") + "," + a(sr.SSID));
```

两点差别值得单列：

1. **数据性质不同**。`getConfiguredNetworks()` 是「这台设备曾经连过哪些 WiFi」，`ScanResult` 是「此刻周围有哪些热点」。后者能做物理位置反查（WiFi 定位库），前者能做用户画像。两种都在外发，性质不同。
2. **采集频度不同**。`cltr/rcvr` 默认 24 小时一次且失败翻 4 倍；`sdk.php` 是主定位请求，跟着定位周期走（`LocationClient` 的 3 分钟扫描 / 5 分钟等待间隔）。

所以「百度侧的上报面」完整描述应是：**已保存配置（`cltr/rcvr`，24h）+ 扫描热点（`sdk.php`，跟随定位周期）+ 位置本身（`gpsz`/`cc.php` 等）** 三条，而不是一条。

需要限定的是：主上行是否真的带 `bloc`，还取决于 `a.a.a.b.m$c.a()` 里那两个开关——只有 `a.a.a.i.i.f || a.a.a.i.i.h` 为真时才追 `&ki=&sn=`，且 `Jni.f()` 加密后的 `bloc` 恒被 put。这两个静态布尔只由 `a.a.a.b.c` 从一条 Binder Message 的 `isneedaptag`/`isneedaptagd` 置位（观测），默认 false。本条的目标选择与触发条件未做动态验证，标**观测（代码路径）+ 未知（实跑行为）**。

### 15.1.2.2 `sdk.php` 请求体的逐键拆解（观测）

`a.a.a.b.m$c.a()` 走的是继承自 `a.a.a.i.g` 的 POST 通路，请求体是 `d` 这个 `Map` 逐项 `k=v&` 拼接。整个 `bloc` 请求的最终形态：

```
POST https://loc.map.baidu.com/sdk.php
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Accept-Encoding: gzip
bd-loc-android: com.mobiletools.systemhelper
alwd: <g.f 字段，可为空>

bloc=<Jni.f(strK)|tp=4>&up=<y.f()>&trtm=<毫秒时间戳>
```

四步拆开：

1. `strK = a.a.a.g.f.w().k()`：拼 `BSSID去冒号,SSID;` 的扫描热点列表。触发前提是 `a.a.a.b.d.i().J != 0` 且扫描缓存 `j()` 非空且 `c() >= 1`，三者任一不满足直接返回 `null`，`bloc` 就只带 `Jni.f(this.j)`（即 URL 参数串本身）。
2. 每个 SSID 过 `a(String)`：超长按 `a.a.a.b.d.i().K` 截断，`&` 与 `;` 替换成 `_`（防止破坏外层 `k=v&` 结构）。BSSID 的冒号直接去掉。最多取 `L=16` 个热点，按 `d` 比较器排序（信号强度优先）。
3. `Jni.f(strK)` = `ee(str, 132456) + "|tp=4"`。**`132456` 是全部 JNI 加密调用里唯一使用的密钥参数**，硬编码，Java 侧从未有其他取值。
4. `up` 来自 `y.f()` → `y.e()`，那是离线定位结果队列（`yo.dat`/`yoh.dat`/`yom.dat`/`yol.dat`/`yor.dat`，位于 `i.h()` 目录）里取出的待发记录，用完即从内存队列弹出。

`trtm` 只是本地时间戳，不是签名也不是 nonce——服务端拿它做什么未知。

### 15.1.2.3 17 个端点的发送方与触发条件（观测）

上一版只列了地址，没说谁发、什么时候发。逐端点查 `f337a` 赋值点与调用链后，实际能得到下面这张表。空白处是**代码里没有任何发送方**的端点：

| 端点 | 发送方类 | 触发 | 请求键 |
|---|---|---|---|
| `loc.map.baidu.com/sdk.php` | `a.a.a.b.m$c`（主）、`a.a.a.b.l$a`（历史补传）、`a.a.a.b.h`、`a.a.a.b.y$a`、`a.a.a.d.i` | 主定位请求；历史库有积压；离线包更新 | `bloc`(+`up`/`trtm`) |
| `loc.map.baidu.com/sdk_ep.php` | 无 | — | — |
| `loc.map.baidu.com/gpsz` | `a.a.a.c.a$C0003a` | `a(double,double,double)` 被调用且 `a.a.a.f101b` 为 false | `gpsz` 或 `gpszb` |
| `loc.map.baidu.com/cc.php` | `a.a.a.b.j$d` | `c(String)` 显式调用 | `q` |
| `itsdata.map.baidu.com/long-conn-gps/sdk.php` | `a.a.a.b.j` | `j.a(File, String)` 的量测回传 | 见 `intime.dat` |
| `loc.map.baidu.com/cfgs/loc/commcfgs` | `a.a.a.b.d$a`（`qt=vdr`）、`a.a.a.b.a$b`（`qt=conf`）、`a.a.a.c.d$b`（`qt=conf`/`grid`） | 配置刷新；`b.a().c(str)` | `qt`+`req` |
| `loc.map.baidu.com/cfgs/indoorloc/indoorroadnet` | `a.a.a.d.m.c.a$c` | 室内路网下载 | `bldg`+`md5` |
| `loc.map.baidu.com/check_indoor_data_update` | 无（只由 `parseConfig` 可改，无发送点） | — | — |
| `loc.map.baidu.com/indoorlocbuildinginfo.php` | `a.a.a.d.a`（`RunnableC0005a`） | 室内楼宇信息请求 | 见类内 |
| `parking.baidu.com/parking/api/parkingdata/getcarportlistforlocation?` | 无 | — | — |
| `ofloc.map.baidu.com/offline_loc` | `a.a.a.f.b$c`、`a.a.a.f.c$b`、`a.a.a.f.f$a` | 离线包 load/update、离线定位、离线行为上报 | `qt`+`req` |
| `ofloc.map.baidu.com/locnu` | `a.a.a.b.x$b` | GNSS 导航消息到达（`z` 的 `case 4`/`case 11`） | `info`+`enl` |
| `ofloc.map.baidu.com/LocBrokerService/do_loc_map_match` | 无 | — | — |
| `ofloc.map.baidu.com/PlanarStartService/detect_parking_exits` | 无 | — | — |
| `daup.map.baidu.com/cltr/rcvr` | `a.a.a.c.f$a`（`qt=cltrw`）、`a.a.a.b.y$a`（`qt=cltrg`/`cldc[n]`） | WiFi 已连接 + 10 秒轮询；或 `y.c().a()` | `cltr[0]`/`info`/`qt` |
| `api.map.baidu.com/sdkcs/verify` | `c.a.c.a.b` | AK 授权校验 | `ak`/`pk`/`mcode`/`cuid`/`pcn`… |
| `dm.wo.com.cn:18080/register`、`/public/ip` | 见第十四章 | 联通链路 | 见第七、八章 |

**五分之二的端点没有发送方。** `sdk_ep.php`、`check_indoor_data_update`、`getcarportlistforlocation`、`do_loc_map_match`、`detect_parking_exits` 这 5 个地址只在 `a.a.a.i.d` 里被声明、被 `parseConfig` 允许改写，但编译进本 APK 的代码里没有任何 `f337a = <该地址>` 或 `new URL(<该地址>)`。它们属于「SDK 预留、本集成方式未启用」。这一点对威胁评估有实际意义：把 `url_config` 指向恶意的解析，对 5 个地址无效，只对剩下 12 个生效。

`a.a.a.i.d.f` 对 `sdk.php` 有 12 处引用，是全部端点里最热的。`f323a`（`sdk_ep.php`）只有 1 处引用，且在 `a.a.a.c.e`（崩溃上传）里——**而这个类只在百度自己的 Service 进程里作为 `UncaughtExceptionHandler` 注册**，并且会读 `/sdcard/traces/error_fs2.dat`。第 12 章再谈这个跨进程文件。

### 15.1.2.4 传输层的两个真实缺陷（观测）

百度 SDK 没有用系统默认的 TLS 校验，它在每个走 `HttpsURLConnection` 的线程里都先执行：

```java
HttpsURLConnection.setDefaultSSLSocketFactory(a.a.a.i.i.g());
```

`i.g()` 的实现是：

```java
public static SSLSocketFactory g() {
    TrustManager[] tm = { new a() };              // a 是自定义 X509TrustManager
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tm, new SecureRandom());
    return ctx.getSocketFactory();
}
```

`a` 的实现只有三行，`checkServerTrusted` 干的事是**只检查证书有效期，不校验证书链**：

```java
public void checkClientTrusted(X509Certificate[] c, String s) { }          // 空
public void checkServerTrusted(X509Certificate[] c, String s) throws ... {
    for (X509Certificate x : c) x.checkValidity();                          // 只看有效期
}
public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
```

由此得到两个后果：

**一是任意证书都能通过。** 攻击者用一张自签的 `loc.map.baidu.com` 证书（比如 `CN=loc.map.baidu.com`、有效期填到 2030 年）就能完成 TLS 握手，客户端不校验签发者。这使得「换掉 `loc_local_config` 指向攻击者的 HTTPS 地址」这个攻击路径的最后一道防线也不存在——不需要真证书，任意 HTTPS 服务都能冒充。

**二是 `setDefaultSSLSocketFactory` 是进程级静态设置。** 它改的是 `HttpsURLConnection` 的全局默认值，而不是单个连接。百度 SDK 跑在自己的 `:remote` 进程（`com.baidu.location.f` 是 `android:process=":remote"`），所以**联通 DM 那条 `http://dm.wo.com.cn` 链路不受影响**（它本来就走明文 HTTP，也不用这个进程）。但在这个 `:remote` 进程内，任何后续的 HTTPS 连接都会继承这个宽松的 `TrustManager`。

第二个缺陷在 `HostnameVerifier`。`a.a.a.i.g$C0021g` 的实现是：

```java
public boolean verify(String host, SSLSession s) {
    return this.f352a.getHost().equals(host);       // 只比 URL 里的 host 与证书 host 是否字面相等
}
```

看起来对，但它比的是**构造时 `new URL(url).getHost()`**。由于 `f337a` 来自可被 `url_config` 改写的静态字段，攻击者只要能写那个文件，`getHost()` 就跟着变，`equals` 永远自洽。这条校验形同虚设。

例外是 `c.a.c.a.m`（百度地图 SDK 的 `api.map.baidu.com` 专用 verifier），它显式 `"api.map.baidu.com".equals(str) → true`，其余回落系统默认。那个比这个严。

## 15.2 内存与实现层面的问题

- `control.b.a()` 里 `throw th;` 在 `try/catch` 之后、`return` 之前，jadx 输出了不可达代码；smali 复核后该方法实为正常返回（观测，属反编译伪影，非真实缺陷）。
- `b.a()` 里 `this.J = "000"` 的三元写成了 `if (this.J != null) this.J = "000"; else this.J = "000";`，jadx 与 smali 一致（观测），是原作者笔误，等价于无条件赋值。
- `if ("5.0" != 0)` 恒真（字符串与整数比较），属无效判断（观测）。
- `SQLite` 删行用列索引当主键值（见第十三章），是真实 bug。
- `m.a(Context)` 直接把路径 `/data/data/com.mobiletools.systemhelper/shared_prefs/...` 写死，非当前用户目录时删不到（多用户场景失效）。
- `OnBootReceiver` 里 `new SIMStateReceiver().a(...)` 每次开机都新建实例并 `registerReceiver`，虽先 `a()` 反注册静态字段，但静态字段在进程重启后为 null，历史实例会泄漏（推断）。

## 15.3 攻击面

- `RegisterHelperService` **exported 且无权限保护**，任意应用可 bind 后：
  - 改 `serverAddress` 把设备数据导向第三方（最严重）
  - 改三个采集间隔（最小 1 秒级高频采集）
  - 删 `shared_prefs` 清状态
  - 开关日志
- `TestActivity` exported，拉起即尝试展示完整设备信息 JSON（含 IMEI/IMSI/ICCID），任何应用可 `startActivity` 触发，但内容只显示在界面（未见写入外部存储）。
- `OnBootReceiver` 用 `priority=2147483647`，属滥用优先级（Android 12+ 对静态 receiver 的 priority 已有限制，实际是否生效取决于 ROM）。

## 15.4 与「后门」的边界

已核查并排除（观测）：

- 无 `DexClassLoader` / `PathClassLoader` / `URLClassLoader`
- 无 `Runtime.exec` / `ProcessBuilder`
- 无 `System.load` / `loadLibrary` 动态加载
- 无反射调用 `su`
- 无响应体解析（不存在「服务器下发 → 执行」链路）
- `liblocSDK8b.so` 的 18 个 JNI 导出全部挂 `com.baidu.location.Jni` / `com.baidu.serverLoc.Jni`，无 `com.mobiletools.*` 相关导出（见 12.1.2）

原生层里确实存在但**在本样本中不可达**的两项，需单独说明以免误判（观测，见 12.2）：

- `libindoor.so` 导入 `system@LIBC`，用 `system(sprintf("gzip -f -d -c \"%s\" > \"%s\"", …))` 与 `tar -C … -xf …` 解压 GNSS/RINEX 星历包，参数是内部文件路径而非网络输入
- `libindoor.so` 在 4 处调用 `ptrace(PTRACE_TRACEME,0,0,0)` 做反调试，但不检查返回值，不改变控制流

这两项都落在 `libindoor.so` 内，而该库的 `DT_NEEDED` 依赖 `libapp_BaiduVIlib.so` 与 `libmml_framework.so`——**包内没有、实机全盘也没有**，`System.loadLibrary("indoor")` 必然抛 `UnsatisfiedLinkError`，被 `catch (Throwable)` 吞掉后 `f1379a=false`，所有入口前置返回 `-1`/`-100`。所以「有命令执行代码」与「会执行命令」是两件事，本样本属前者不属后者（推断，证据极强）。

结论（推断，证据强）：它是一款**权限很高、采集很多、上报单一**的运营商定制 DM 客户端，不是通用远控。风险集中在「敏感数据采集 + 明文传输 + 可被本机应用劫持上报地址」三点。原生层没有额外的远控能力，唯一实质缺陷是百度 SDK 的下行 AES 密钥全局硬编码（12.1.4）。

# 十六、未知项

1. ~~`e.e`（用户同意开关）在本机的实际取值~~ 已确认：本机走小米分支，`e.e = (device_provisioned==1)`，实机恒 true，采集链路全开（见 15.1.1）。仍未知的是 `operator_service_improve_plan` 在 vivo 机型上的系统默认值。
2. 服务端 403 之后的真实行为：是否校验 `sign`、是否有时间窗防重放、`416` 的业务语义、响应体格式。全部因 WAF `UrlACL` 拦截不可达。
3. `RegType` 是否还有 `H` 等其他取值。本版本代码中 `H` 无产生点，但 `b.a()` 对未知 `RegType` 是宽容的（走 else 分支），所以服务端可能支持更多类型。
4. `SubType` 的 `{RAM, ROM, FREE}` 是否被服务端使用；`DeviceType` 编码 `000004/000005/000` 的完整对照表只有两个值有证据。
5. `TestActivity` 的实际渲染内容未经实机验证（未拉起，以免扰动设备状态）。
6. 应用是否在某些机型上真的会上报（本机电信卡不满足联通门控，无法观察到真实 POST 流量）。
7. `RegisterJobService` 的 `onStartJob` 只打日志就 `return true`（表示「任务还在跑」）且从不 `jobFinished`，若被调度会占住任务槽；但代码里没有任何 `JobScheduler` 调度点，属未使用组件。
8. 该 APK 是随哪个机型/哪个 ROM 版本预置的（`CN=NewDM`、`O=CU` 指向联通定制，但具体机型清单未知）。
9. `liblocSDK8b.so` 里除 `ldkaiv` 之外的 JNI（`encrypt`/`ee`/`encodeNotLimit`/`a`/`b`/`c`/`murmur`/`gsr`）具体算法未逐指令还原：已知不含标准 AES S-box 与 MD5 常量，属自定义置换/异或体系，未做等价的算法级复现。
10. `ldkaiv` 内两段运行时自检（`(14x²−19x−19)%25` 与 `7y²−1−x²`）的确切语义未动态验证，只能判断为「为 0 时提前返回」，是否为授权校验/过期判断未知。
11. 百度 SDK 的 `cltr/rcvr` 上报（15.1.2）在本机未观测到真实流量：`i.l()` 恒 false 不构成拦截，但 `g.f.w().p()` 要求 WiFi 已连接，且首次上报需 `wcnf.dat` 不存在或超过 `frq` 周期；未做抓包佐证。
12. 服务端下发 `cfg.frq` 或其他配置项后，客户端行为的实际变化范围（是否只影响上报频率）未动态验证。

# 附录 A：关键类索引

| 类 | 职责 |
|---|---|
| `com.mobiletools.systemhelper.control.b` | 报文模型 + 40 键 JSON 组装 |
| `com.mobiletools.systemhelper.control.f` | 上报线程（门控 + POST + 落库） |
| `com.mobiletools.systemhelper.control.d` | 历史补传线程（`typef` + `dmregister`） |
| `com.mobiletools.systemhelper.control.e` | 应用使用统计采集线程 |
| `com.mobiletools.systemhelper.control.c` | 取 IP 线程（死代码） |
| `com.mobiletools.systemhelper.control.a` | TelephonyCallback + 信号采集 + 百度定位 |
| `c.d.a.a.l` | 设备信息编排（`getCurDeviceInfo`）+ 厂商分发（`f1325a` 型号→厂商表） |
| `c.d.a.a.a` | 设备信息读取基类（默认分支，卡信息/小区信息主力） |
| `c.d.a.a.j` | 小米专用读取（MIUI 版本、cust_hardware） |
| `c.d.a.a.i` | vivo 专用读取（`ro.vivo.op.entry` 含 UNICOM 走不同属性） |
| `c.d.a.a.d` | OPPO 专用读取 |
| `c.d.a.a.k` | ZTE 专用读取（`dm_user_agreement`） |
| `c.d.a.a.f` | realme 专用读取（`ro.build.display.id` / `ro.build.hardware.version`） |
| `c.d.a.a.c` | nubia 专用读取（仅 `NX659J`/`NX651J`/`angelcare N9`） |
| `c.d.a.a.g` | 三星专用读取（`ril.sw_ver` / `ril.hw_ver`） |
| `c.d.a.a.b` / `c.d.a.a.e` / `c.d.a.a.h` | 联想 / 一加 / 天玑，只调共用 `b()`，无私有属性 |
| `c.d.a.b.c` | MD5 / AES 两个原语，RSA 委托给 `c.d.a.b.k` |
| `c.d.a.b.k` | `RSAHelper`：读 `assets/pub.cer`、`X.509` 解析、`RSA/ECB/PKCS1Padding` 加密 |
| `c.d.a.b.l` | 反射工具（`SubscriptionManager.getSubId`、`miui.telephony.TelephonyManager`） |
| `c.d.a.b.h` | 内存/存储采集（`SubType` 的 `RAM`/`ROM`/`FREE` 来源，`ro.boot.dram_info` + `StatFs`） |
| `c.d.a.b.i` | 日志封装（受 `e.f1332a` 开关控制） |
| `com.mobiletools.systemhelper.control.DMApplication` | 自定义 `Application`，`onCreate` 即注册 TelephonyCallback（4.3.1） |
| `c.d.a.b.g` | HTTP POST 封装 |
| `c.d.a.b.d` | `public/ip` GET（死代码） |
| `c.d.a.b.a` | 5 条 AlarmManager 调度 |
| `c.d.a.b.e` | 全局常量（URL、周期、开关） |
| `c.d.a.b.m` | SharedPreferences 与联通判定 |
| `c.d.a.b.f` / `c.d.a.b.n` | `systemhelper` / `signalhelper` 库 |
| `c.d.a.b.o` | SigInfo 模型（30 键） |
| `c.d.a.b.b` | AppInfo 模型（11 键） |
| `com.baidu.location.Jni` | 百度定位 so 的 Java 包装（9 个 native） |
| `com.baidu.location.indoor.mapversion.IndoorJni` | 室内定位 so 的 Java 包装（16 个 native，实际不可用） |
| `a.a.a.i.d` | 百度 SDK 端点常量（9 个静态字段，全包共 17 个硬编码 URL） |
| `a.a.a.c.f` | 百度侧 WiFi SSID 采集与 `cltr/rcvr` 上报（15.1.2） |
| `a.a.a.b.z` | 百度 SDK 内部 10 秒消息泵，驱动 `case 4` 采集 |

# 附录 B：证据来源清单

- 静态：`apktool` 3.0.3 全量 smali + `jadx` 全量 Java 源，交叉核对 6 处 bad-code（`control/b`、`SIMStateReceiver`、`control/a` 等）
- 原生静态：`readelf` / `objdump` / `nm` / `strings`（binutils，Termux aarch64）解析两个 so 的头、节表、动态符号、重定位与反汇编；`.rodata` 字符串用 Python 按库内异或原语（`out[i]=src[i]^((len+i)&0xFF)`）全量还原，`libindoor.so` 解出 228 条、`liblocSDK8b.so` 解出 `ldkaiv` 的 `key|iv`
- 原生反编译：IDA Pro 9.4 + Hex-Rays（远端 x86_64 计算节点 `f11r1n06`，128 核 / 1 TB 内存），`idat94 -A -B` 建库后由自写 IDAPython 脚本按导出表修复函数边界、逐函数 `decompile()`，共产出 5256 个函数体（`liblocSDK8b` 1383、`libindoor` 3872），产物见 `work/systemhelper/ida/`
- 加密：Python 3.14 + `cryptography` 50.0.2 实跑 `MD5 → AES/ECB/PKCS5` 与 `RSA/ECB/PKCS1` 两条路径
- 实机（`ad`，uid=2000）：`dumpsys package`、`dumpsys alarm`、`dumpsys jobscheduler`、`getprop`、`logcat`
- 网络：`curl` 只读探测 `dm.wo.com.cn:18080` 两个路径，未构造上报请求；另对 `daup`/`loc`/`ofloc`/`api`.map.baidu.com 各探一次根路径，均只取状态码
- 原生加载状态：实机 `dumpsys package` 确认 `extractNativeLibs=false`、`primaryCpuAbi=arm64-v8a`；`ls` 核对 `/system/lib64`、`/vendor/lib64` 无 `libapp_BaiduVIlib.so` 与 `libmml_framework.so`
