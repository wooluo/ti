# ThreatIntel Auto Popup 脚本使用说明

## 概述

这个脚本可以帮助你在浏览网页时，自动检测并查询IP、域名、MD5、SHA1和URL的威胁情报，并以弹窗形式显示结果。

## 获取API Tokens

1. 访问 [https://ti.qianxin.com/url/user/account/api](https://ti.qianxin.com/url/user/account/api)
2. 登录你的奇安信账号
3. 在API管理页面中，你可以获取到以下两个重要的API凭证：
   - 情报沙箱 Token (sandbox)
   - 威胁情报 API Key (threat)

## 配置脚本

1. 打开 `sandbox_query_optimized.user.js` 文件
2. 找到配置区 (`CONFIG` 变量)
3. 替换以下内容为你自己的API凭证：

```javascript
// 配置区
const CONFIG = {
    // 替换为你自己的 Token 和 API Key
    api_tokens: {
        sandbox: '你的情报沙箱token',
        threat: '你的威胁情报api key'
    },
    // 其他配置...
};
```

## 安装说明

1. 安装 Tampermonkey 扩展（适用于Chrome、Firefox等浏览器）
2. 点击 Tampermonkey 图标，选择"添加新脚本"
3. 复制 `sandbox_query_optimized.user.js` 的内容到编辑器中
4. 保存脚本

## 使用方法

1. 脚本会自动检测你浏览的网页上的IP、域名、MD5、SHA1和URL
2. 当你鼠标悬停在这些内容上时，脚本会自动查询并显示威胁情报
3. 你也可以选中文本，脚本会弹出查询结果

## 功能特点

- 支持自动检测和查询IP、域名、MD5、SHA1和URL
- 支持鼠标悬停和选中文本两种触发方式
- 提供缓存功能，避免重复查询
- 支持自定义配置，如查询超时、弹窗显示时间等
- 当检测到APT相关信息时，会显示红色的APT标记
- 支持处理带端口的IP地址

## 注意事项

1. 请确保你获取的API凭证是有效的
2. 避免在短时间内进行大量查询，以免触发API限制
3. 如果你遇到任何问题，可以查看浏览器的控制台日志以获取更多信息
4. 威胁分析平台（ALPHA）云API只有两个白名单IP地址可以使用，需要获取到当前出口IP，然后修改才能使用此脚本# ti
# ti
