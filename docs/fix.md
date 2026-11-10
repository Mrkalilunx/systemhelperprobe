# 修复建议

## 客户端侧

按优先级：

1. 给服务加 `android:permission`，`protectionLevel` 取 `signature`，只允许同签名组件绑定，改动最小
2. 服务内 `onBind` 或每个事务入口用 `Binder.getCallingUid()` 校验调用方 uid 必须等于自身 uid 或系统 uid
3. 把 `serverAddress` 从可写外部入口下线。地址属产品配置，不该有运行时可改接口
4. 事务码 2、3、4 一并删除或加同等校验。它们都不存在合理的外部调用方

## 平台侧

5. 加强预装应用清单审计，重点是导出组件与 `android:permission` 的配对检查。`privapp-permissions` 白名单里 `MODIFY_PHONE_STATE` 重复声明且清单未申请，说明这份配置缺乏系统性复核
6. 把 `serverAddress` 从 SharedPreferences 挪到受 SELinux 保护或签名校验的配置源，作为第二道闸

第 1 条与第 2 条任一条即可封住 binder 改道。第 3 条是根治：只要地址不可在运行时改写，即使服务仍导出，也没有可改的对象。

## 验证修复

改法落地后可以拿本仓库的 PoC 直接验证，不需要另写测试应用：

1. 装上修复后的 SystemHelper 与 `dev.poc.syshelperprobe`
2. 打开 PoC，看顶部是否仍显示 `RegisterHelperService exported=true binder=true`
3. 点「覆写地址」

期望结果随采用的修复方式不同：

| 采用的修复 | 期望 |
|---|---|
| 加 `signature` 权限 | `bindService` 返回 false，状态停在「未绑定」，界面无法进入劫持态 |
| `getCallingUid()` 校验 | 绑定成功但事务码 1 抛 `SecurityException`，或写入被静默忽略，状态仍为「未劫持」 |
| 下线 `serverAddress` 入口 | 事务码 1 执行成功但 `m.d()` 不再读该键，报文仍发往 `dm.wo.com.cn`，环回口收不到 POST |

第三种情况下 PoC 界面会显示「已劫持」却收不到报文。这不是误报，恰恰说明写入生效了但已被忽略，属修复生效的表现。
