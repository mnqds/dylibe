#!/bin/bash
# ============================================================
#  把 WatermarkGuard.dylib 注入已砸壳 IPA，并重打包成未签名 IPA
#
#  用法：
#     ./pack_ipa.sh <已砸壳.ipa> [输出.ipa]
#
#  依赖：unzip / zip / optool（或 insert_dylib）/ codesign
# ============================================================
set -euo pipefail

IPA="${1:-}"
OUT="${2:-}"

if [ -z "$IPA" ]; then
  echo "用法: $0 <已砸壳.ipa> [输出.ipa]"
  exit 1
fi

DYLIB="WatermarkGuard.dylib"
[ -f "$DYLIB" ] || { echo "缺少 $DYLIB，请先 make"; exit 1; }

WORK="build_$$"
rm -rf "$WORK"
mkdir -p "$WORK"

echo "==> 解包 $IPA"
unzip -q "$IPA" -d "$WORK"

APP=$(find "$WORK/Payload" -maxdepth 1 -name "*.app" -type d | head -n 1)
[ -n "$APP" ] || { echo "Payload 下没有 .app"; exit 1; }

EXE_NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP/Info.plist")
EXE="$APP/$EXE_NAME"
[ -f "$EXE" ] || { echo "找不到主二进制: $EXE"; exit 1; }

echo "==> App: $APP"
echo "==> 主二进制: $EXE_NAME"

# 1) 放 dylib
mkdir -p "$APP/Frameworks"
cp "$DYLIB" "$APP/Frameworks/$DYLIB"

# 2) 注入 load command
if command -v optool >/dev/null 2>&1; then
  optool install -c load -p "@executable_path/Frameworks/$DYLIB" -t "$EXE"
elif command -v insert_dylib >/dev/null 2>&1; then
  insert_dylib --inplace --strip-codesig --all-yes \
    "@executable_path/Frameworks/$DYLIB" "$EXE"
elif command -v azule >/dev/null 2>&1; then
  azule -i "$EXE" -o "$EXE" -f "$APP/Frameworks/$DYLIB"
else
  echo "缺少注入工具，请先安装 optool："
  echo "  brew install optool   或   下载 optool 源码 make 后放进 PATH"
  exit 1
fi

# 3) 清除原有签名（主二进制必须清；dylib 保留 ad-hoc 签名更保险）
echo "==> 清除签名"
codesign --remove-signature "$EXE" 2>/dev/null || true
rm -rf "$APP/_CodeSignature"
# dylib 自带 ldid / codesign ad-hoc 签名（重签名工具若整体重签会自动覆盖）
if command -v ldid >/dev/null 2>&1; then
  ldid -S "$APP/Frameworks/$DYLIB" 2>/dev/null || true
else
  codesign -f -s - "$APP/Frameworks/$DYLIB" 2>/dev/null || true
fi
# 若扩展里有二进制，也一并清签名
find "$APP" -type f -perm -u+x ! -path "$EXE" ! -path "$APP/Frameworks/$DYLIB" | while read -r f; do
  codesign --remove-signature "$f" 2>/dev/null || true
done

# 4) 核对 load command
echo "==> 核对注入结果"
otool -L "$EXE" | grep -i watermark || echo "!! 未发现 WatermarkGuard，请检查 optool 输出"

# 5) 重打包（用 store 模式更兼容，避免某些安装器解压异常）
OUT="${OUT:-${IPA%.ipa}-wg-unsigned.ipa}"
# 转成绝对路径，避免下面 cd 进工作目录后把产物写进临时目录
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
rm -f "$OUT"
( cd "$WORK" && zip -qry "$OUT" Payload )
rm -rf "$WORK"

echo "==> 输出: $OUT"
echo "==> 用你的重签名工具安装即可（TrollStore / Sideloadly / ESign 等）"
