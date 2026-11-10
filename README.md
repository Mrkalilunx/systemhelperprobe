# SystemHelper Binder PoC

针对中国联通定制 DM 客户端 `com.mobiletools.systemhelper`（SystemHelper 3.0.0-20231222）的漏洞验证工程。

漏洞：对外导出的 `com.mobiletools.systemhelper.service.RegisterHelperService` 既没有 `android:permission` 保护，也没有对调用方做任何 uid 或签名校验，任意本机应用 bind 之后即可通过 Binder 事务码改写上报地址 `serverAddress`，把本应发往联通 DM 平台 `http://dm.wo.com.cn:18080/register` 的设备数据重定向到第三方服务器。

本仓库把漏洞链路完整复现、留下可核对的证据、给出修复建议。不含攻击他人的代码，运行前提是对自己的测试设备有完全控制权。

## 漏洞事实

清单里该服务的声明（`AndroidManifest.xml`）：

```xml
<service android:exported="true"
         android:name="com.mobiletools.systemhelper.service.RegisterHelperService">
    <intent-filter>
        <action android:name="com.mobiletools.systemhelper.service.IRegisterHelperService"/>
    </intent-filter>
</service>
```

同一份清单里，同应用的 `RegisterJobService` 写了 `android:permission="android.permission.BIND_JOB_SERVICE"`，`RegisterHelperService` 一个权限都没写，属遗漏而非设计。

服务端点在 `RegisterHelperService$a.smali` 的 `onTransact`，共 5 个事务码：

| code | 方法 | 效果 | 风险 |
|---|---|---|---|
| 1 | `a(String)` | 写 `serverAddress` | 上报数据改道，最高 |
| 2 | `a(int)` | 写三个采集间隔 | 采集频率被拉到秒级 |
| 3 | `b()` | 删 `shared_prefs/...xml` | 抹掉本地状态与待补传队列 |
| 4 | `a(boolean)` | 写 `preference_enable_log` | 打开目标日志 |
| 5 | `a()` | 读日志开关 | 唯一有返回值的读取 |

事务码 1 的落点与消费点：

```java
// com.mobiletools.systemhelper.service.RegisterHelperService$a
public void a(String str) { m.a(RegisterHelperService.this.f1420b, str); }

// c.d.a.b.m
public static void a(Context context, String str) { b(context, "serverAddress", str); }

// 上报线程每次发之前都重读，所以改完立即生效，不用重启目标进程
public static String d(Context context) {
    return e.f1333b ? e.l : a(context, "serverAddress", e.l);
}
```

`e.f1333b` 是调试开关，全工程没有赋值点，恒为 false，于是 `SharedPreferences` 里的覆盖值永远优先。

## 危害

- 数据改道：设备数据不再进联通 DM 平台，落到第三方。运营商侧的设备管理与故障定位数据缺一块
- 元数据明文暴露：URL 查询串里的 `ver`、`model`、`manuf`、`sign` 均为明文，第三方可直接读
- 密文留存：body 是 AES/ECB 密文，第三方可无限留存
- 可用性破坏：事务码 2 可把采集间隔改到秒级，事务码 3 可清掉待补传队列
- 上报节奏劫持：第三方返回 200 即可让目标认为上报成功，从而触发历史补传线程
- **明文可读**：事务码 4 能打开目标日志开关且无权限保护，之后 `adb logcat -s RegisterThread` 可读到完整明文 JSON
- **源 IP 暴露**：设备直连目标地址，第三方免费得到源 IP，可定位到城市与运营商
- **静默可读信息可被打包**：机型、系统版本、RAM、剩余存储等无需任何权限即可读取，同源外发即进入攻击者手里

影响范围比「联通用户」宽。上报门控是 `(WiFi && MCC=460) || (!roaming && 联通卡)`，只要连着 WiFi 且插任意中国大陆运营商卡，报文就会真的发出去，而该应用随定制 ROM 预装。

### 不成立的部分

- 靠穷举单条密文拿不到明文：端上应用无权时约 10^50 种候选，拿到定位与电话后约 10^34。这份难度几乎全部来自卡库未泄露，不来自加密算法
- 不能只说「加密了所以安全」：事务码 4 的明文日志通道与先验信息泄露都不依赖破密，任一条成立即可拿到明文
- 普通第三方应用读不到目标日志，`READ_LOGS` 的 `protectionLevel` 为 `signature|privileged|development`，这条通道只对有 adb 权限者成立

## 文档

| 文件 | 内容 |
|---|---|
| `docs/exploit.md` | 利用链实操：加密强度、穷举恢复明文、第三方视角的成本核算、触发条件、实测记录、还原 |
| `docs/fix.md` | 客户端与平台侧的修复建议 |
| `docs/analysis.md` | 完整逆向分析报告，含 .so 分析、百度定位上报面、调度时序，已脱敏 |
| `docs/evidence.md` | 反编译证据摘录与逐条核对结论 |
| `docs/build.md` | 工程结构、无 Gradle 构建、验证步骤 |

## 授权与免责

本工程用于自有测试设备上的安全研究复现。不要用于未获授权的设备，不要指向他人的服务器。PoC 默认只监听环回口，不向任何公网地址发数据。
