# 第三方声明

本项目自身是 MIT（见 `LICENSE`）。下面两处是移植/借鉴来的部分，各自保留原版权声明：

## src/subs.rs — zen-gate

节点 URI 解析（vmess / vless / trojan / anytls / hy2 / tuic / ss / socks，含 uTLS 指纹白名单与 ss 的三种 base64 形状）移植自
[zen-gate](https://github.com/LAGcomcom/zen-gate) 的 `internal/subs/parse.go`。

```
MIT License

Copyright (c) 2026 LAGcomcom
```

那些解析上的坑（`*_auto` uTLS 别名、`fp=unsafe` 会让整份配置被 sing-box 拒掉、ss 的 legacy base64 形状）
是上游用生产流量换来的，所以这里是移植而不是重写。

## assets/index.html — workbuddy-manager

底部浮动 dock 的视觉与交互参数（容器圆角/毛玻璃、项 44→68px 放大、图标 21→34px、
150px 影响半径、hover tooltip 在上方）取自
[workbuddy-manager](https://github.com/ithtelab/workbuddy-manager) 的 `web/components/ui/floating-dock.tsx`。

```
MIT License

Copyright (c) 2026 WorkBuddy Manager contributors
```

原实现是 React + motion/react（`useMotionValue` / `useSpring`）；本项目没有前端框架也没有构建步骤，
用原生 JS + CSS 重写（`requestAnimationFrame` + smoothstep 曲线）。**没有**引入 React 或 motion。
