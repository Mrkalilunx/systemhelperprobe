#!/usr/bin/env bash
# SystemHelper Binder PoC 的无 Gradle 构建脚本
#
# 只依赖四件东西：javac、aapt2、d8、apksigner
# 不用 Gradle，是因为 AGP 会拉一整套依赖，在 CI 上既慢又不稳
#
# 用法
#   scripts/buildapk.sh                 默认 debug 签名
#   ANDROIDJAR=/path/android.jar scripts/buildapk.sh
#   KS=/path/your.jks KS_PASS=xxx KEY_ALIAS=a KEY_PASS=xxx scripts/buildapk.sh
#
# 产物
#   build/systemhelperprobe-debug.apk
#   build/systemhelperprobe-debug.apk.sha256

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/app/src/main"
OUT="$ROOT/build"
NAME="systemhelperprobe-debug.apk"

say() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------- 工具定位

need() {
    command -v "$1" >/dev/null 2>&1 || {
        say "缺少工具 $1"
        say "Termux: pkg install openjdk-21 aapt2 d8 apksigner"
        say "Ubuntu: 用 sdkmanager 装 build-tools"
        exit 1
    }
}

need javac
need aapt2
need d8
need apksigner

# ---------------------------------------------------------------- android.jar

findjar() {
    if [ -n "${ANDROIDJAR:-}" ] && [ -f "$ANDROIDJAR" ]; then
        printf '%s' "$ANDROIDJAR"
        return 0
    fi
    local sdk spec cand
    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
               "$HOME/Android/Sdk" "/usr/local/lib/android/sdk"; do
        [ -n "$sdk" ] || continue
        for spec in android-33 android-34 android-35 android-36 android-32; do
            cand="$sdk/platforms/$spec/android.jar"
            if [ -f "$cand" ]; then
                printf '%s' "$cand"
                return 0
            fi
        done
    done
    return 1
}

ANDROIDJAR="$(findjar || true)"
if [ -z "$ANDROIDJAR" ]; then
    say "找不到 android.jar"
    say "请设 ANDROIDJAR 指向 platforms/android-33/android.jar"
    say "或自行下载 platform-33-ext3_r03.zip 解出 android-13/android.jar"
    exit 1
fi
say "android.jar = $ANDROIDJAR"

# ---------------------------------------------------------------- 清理

rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"

# ---------------------------------------------------------------- 资源与清单

# 没有 res 目录，aapt2 compile 会报错，所以只走 link
say "aapt2 link"
aapt2 link \
    -o "$OUT/base.apk" \
    -I "$ANDROIDJAR" \
    --manifest "$SRC/AndroidManifest.xml" \
    --java "$OUT/gen" \
    --min-sdk-version 26 \
    --target-sdk-version 33 \
    --auto-add-overlay

# ---------------------------------------------------------------- 编译

find "$SRC/java" "$OUT/gen" -name '*.java' > "$OUT/sources.txt"
say "源码 $(wc -l < "$OUT/sources.txt") 个"
say "javac"

javac -encoding UTF-8 \
    -source 8 -target 8 \
    -bootclasspath "$ANDROIDJAR" \
    -classpath "$ANDROIDJAR" \
    -nowarn \
    -d "$OUT/classes" \
    @"$OUT/sources.txt"

# ---------------------------------------------------------------- dex

say "d8"
find "$OUT/classes" -name '*.class' > "$OUT/classes.txt"
d8 \
    --release \
    --min-api 26 \
    --lib "$ANDROIDJAR" \
    --output "$OUT/dex" \
    @"$OUT/classes.txt"

# ---------------------------------------------------------------- 打包

say "打包"
cp "$OUT/base.apk" "$OUT/$NAME"
( cd "$OUT/dex" && zip -q -X "$OUT/$NAME" classes.dex )

# aapt2 link 出的包未对齐，apksigner 之前必须有 4 字节对齐
if command -v zipalign >/dev/null 2>&1; then
    say "zipalign"
    zipalign -f 4 "$OUT/$NAME" "$OUT/aligned.apk"
    mv "$OUT/aligned.apk" "$OUT/$NAME"
else
    say "跳过 zipalign（未安装），仅用于测试安装"
fi

# ---------------------------------------------------------------- 签名

if [ -n "${KS:-}" ] && [ -f "$KS" ]; then
    say "用自带密钥签名 $KS"
    apksigner sign \
        --ks "$KS" \
        --ks-key-alias "${KEY_ALIAS:-poc}" \
        --ks-pass "pass:${KS_PASS:?需要 KS_PASS}" \
        --key-pass "pass:${KEY_PASS:-$KS_PASS}" \
        --out "$OUT/signed.apk" \
        "$OUT/$NAME"
    mv "$OUT/signed.apk" "$OUT/$NAME"
else
    say "生成临时 debug 密钥"
    DEBUGKS="$OUT/debug.jks"
    keytool -genkeypair -v \
        -keystore "$DEBUGKS" \
        -storepass android -keypass android \
        -alias poc -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=SystemHelper Poc, O=poc, C=CN" >/dev/null 2>&1
    apksigner sign \
        --ks "$DEBUGKS" \
        --ks-key-alias poc \
        --ks-pass pass:android \
        --key-pass pass:android \
        --out "$OUT/signed.apk" \
        "$OUT/$NAME"
    mv "$OUT/signed.apk" "$OUT/$NAME"
fi

apksigner verify --print-certs "$OUT/$NAME" > "$OUT/verify.txt" 2>&1 || true

# ---------------------------------------------------------------- 指纹

( cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256" )

say ""
say "完成 $OUT/$NAME"
say "大小 $(wc -c < "$OUT/$NAME") 字节"
say "sha256 $(cut -d' ' -f1 "$OUT/$NAME.sha256")"
say ""
say "安装 adb install -r $OUT/$NAME"
