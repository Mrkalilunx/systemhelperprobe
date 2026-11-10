# 工程结构、构建与验证

## 工程结构

| 路径 | 内容 |
|---|---|
| `app/src/main/java/dev/poc/syshelperprobe/probe.java` | 5 个事务码的投递实现、广播触发器、服务探测 |
| `app/src/main/java/dev/poc/syshelperprobe/sink.java` | 环回口上的最小 HTTP 接收器，充当第三方服务器 |
| `app/src/main/java/dev/poc/syshelperprobe/mainactivity.java` | 全代码构建的演示界面 |
| `app/src/main/AndroidManifest.xml` | 只申请 INTERNET，不申请任何敏感权限 |
| `scripts/buildapk.sh` | 无 Gradle 构建，CI 与本地共用 |
| `scripts/bruteplaintext.py` | 密文明文穷举恢复，已在真实报文上验证 |
| `.github/workflows/buildapk.yml` | CI 构建、artifact 上传、打 tag 自动发 release |
| `docs/exploit.md` | 加密强度、穷举恢复明文、成本核算、触发条件、实测记录、还原 |
| `docs/fix.md` | 修复建议与修复验证 |
| `docs/evidence.md` | 反编译证据摘录与逐条核对结论 |
| `docs/analysis.md` | 完整逆向分析报告，已脱敏 |

## 构建

本地（Termux，已验证）：

```sh
pkg install openjdk-21 aapt2 d8 apksigner
ANDROIDJAR=/path/to/android.jar bash scripts/buildapk.sh
```

本地（Linux 或 macOS，有 Android SDK）：

```sh
bash scripts/buildapk.sh
```

脚本按 `ANDROIDJAR`、`ANDROID_HOME`、`ANDROID_SDK_ROOT`、常见默认路径的顺序找 `android.jar`。产物是 `build/systemhelperprobe-debug.apk`，附 `.sha256` 与 `verify.txt`。

## 构建环境

- Termux aarch64，OpenJDK 21.0.13，aapt2 2.20-android-16.0.0_r4，D8 9.2.4-dev，apksigner 0.9
- `android.jar` 取自 `platform-33-ext3_r03.zip` 内的 `android-13/android.jar`（27,139,018 字节）
- 本机未装 zipalign，构建时跳过对齐，仅用于测试安装

## 构建结果

```
$ ANDROIDJAR=.../android-13/android.jar bash scripts/buildapk.sh
android.jar = .../android-13/android.jar
aapt2 link
源码 4 个
javac
d8
打包
跳过 zipalign（未安装），仅用于测试安装
生成临时 debug 密钥

完成 .../build/systemhelperprobe-debug.apk
大小 20873 字节
sha256 00573d72b9003b4d8d3fc70d43754745f07c0940ee9ab06b830bd4fade2236a8
```

APK 内容：

```
  2540  AndroidManifest.xml
    40  resources.arsc
 23264  classes.dex
   412  META-INF/POC.SF
  1218  META-INF/POC.RSA
   285  META-INF/MANIFEST.MF
```

`aapt2 dump badging` 关键行：

```
package: name='dev.poc.syshelperprobe' ... compileSdkVersion='33'
minSdkVersion:'26'
targetSdkVersion:'33'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.ACCESS_NETWORK_STATE'
launchable-activity: name='dev.poc.syshelperprobe.mainactivity'
```

`apksigner verify --print-certs`：

```
V3.0 Signer: certificate DN: CN=SystemHelper Poc, O=poc, C=CN
V3.0 Signer: certificate SHA-256 digest: 0b82a2e559e13d18a1885a8bffc785723c0b579244ef5e7d57992fa1d0a2b023
```

上面的大小与 sha256 是历史构建记录。APK 不是逐字节可复现的，签名里带时间戳，重新构建出的字节会不同。

## 验证

安装到测试机后按界面顺序操作。

1. 点「开始监听」，在环回口 `127.0.0.1:8080` 起接收器。Android 的环回口是全设备共享的，目标进程自己就会连过来，不需要 VPN 也不需要 root
2. 确认界面顶部 `RegisterHelperService exported=true binder=true`，状态显示「未劫持」
3. 点「覆写地址」，事务码 1 把 `serverAddress` 改成 `http://127.0.0.1:8080/register`，界面转为「已劫持」并变橙
4. 点「触发上报」。目标侧 `OnBootReceiver` 的 `onReceive` 对非 `BOOT_COMPLETED` 的 action 会直接走 `b.a(ctx,"B")`，等于跳过开机 4 分钟与 6 小时定时，立刻跑一次完整采集
5. 接收器应打印 `POST /register?ver=5.0&model=...&manuf=...&sign=...` 与密文 body，同时把明文头与 body 的 base64 追加到 `/sdcard/Android/data/dev.poc.syshelperprobe/files/capture/capture.log`
6. 点「还原默认」，状态回到「未劫持」，测试机恢复出厂行为

第 5 步能否看到 POST 取决于当时的网络形态，按 `docs/exploit.md` 里「触发条件」那张表判断：

- 连着 WiFi 且插任意中国大陆运营商卡（移动、联通、电信都行）→ 会 POST
- 移动数据且插联通卡 → 会 POST
- 移动数据且插电信或移动卡 → 不会 POST，按门控落本地队列

看不到 POST 不代表漏洞不成立，可改用下面的日志闭环取证，它不依赖运营商。

不依赖运营商的日志闭环（不需要 root）：

1. 点「开目标日志」，事务码 4 把 `preference_enable_log` 写进目标 prefs
2. 点「读日志开关」，事务码 5 读回 `true`，这一条证明字节确实进了目标进程的 prefs
3. 点「触发上报」
4. 在另一个终端看：

```sh
adb logcat -d -s OnBootReceiver:V RegisterThread:V
```

能看到 `OnBootReceiver onReceive-->intent action: dev.poc...` 与后续 `RegisterThread` 输出。`i.a()` 的打印被 `e.f1332a` 门控，默认关着，只有事务码 4 能打开它，所以这几行本身就是「外部应用改了目标内部状态」的直接证据。`adb logcat` 用 uid 2000 即可读，不需要 root 或 Shizuku 提权。

零外发验证：不要开飞行模式，也不要拔卡，保持 SIM 在网，只把 WiFi 打开，然后做第 3 到 6 步。

原因是 `m.a(bVar)` 取的是 `CellIdentity` 里拼出来的 `MCC+MNC`（`a.java` 的 `getNetworkRegistrationInfoList` 那段）。飞行模式或拔卡之后没有蜂窝注册，`CellIdentity` 拿不到，`MNC1`/`MNC2` 会是空串，`startsWith("460")` 为假，门控反而不过，什么都不会发。要过门控必须让卡在网。

真正保证不出设备的是地址已被劫持到 `127.0.0.1`，不是飞行模式。只要做了第 3 步，报文只会进环回口。

## 本地未验证项

以下需要在真实设备上跑，本地只做了构建与静态核对：

- 目标设备上 `bindService` 是否成功（取决于目标是否被预装且未被停用）
- 联通卡下接收器是否真收到 POST
- 非联通卡下 `adb logcat -s RegisterThread` 是否按预期输出

## 代码层面的自检

- 只用显式 `ComponentName` 绑定与发广播，不依赖 intent-filter 匹配，避免被包可见性或 filter 变化影响
- `Parcel` 在 `finally` 里 `recycle()`，异常路径不泄漏
- 接收器只绑 `127.0.0.1`，不出网
- 破坏性事务码 2 与 3 只留了方法，没有接到界面上，避免误点
- 还原有四层兜底，手动按钮、`onStop`、`onServiceConnected` 自愈、标记清理，默认全部生效
- 还原写的是 `probe.DEFAULTURL`，与 `c.d.a.b.e.l` 字面量一致，等价于把 `serverAddress` 键恢复成出厂状态
- 不收任何敏感权限，`INTERNET` 仅用于本地 socket
