<template>
  <section class="stack-page">
    <div class="page-intro"><div><h2>设置</h2><p>控制应用行为、网络保护和更新策略。</p></div></div>
    <div class="settings-grid">
      <article class="surface-card settings-section">
        <span class="card-kicker">应用</span><h3>常规</h3>
        <label class="setting-row"><span><strong>开机启动</strong><small>登录 Windows后自动启动控制界面</small></span><input type="checkbox" /></label>
        <label class="setting-row"><span><strong>关闭到托盘</strong><small>关闭窗口时保持后台运行</small></span><input type="checkbox" checked /></label>
      </article>
      <article class="surface-card settings-section">
        <span class="card-kicker">网络</span><h3>安全保护</h3>
        <label class="setting-row"><span><strong>IPv6接管</strong><small>阻止流量从物理网卡泄漏</small></span><input type="checkbox" checked /></label>
        <label class="setting-row"><span><strong>Kill Switch</strong><small>隧道异常时阻止直连回落</small></span><input type="checkbox" /></label>
      </article>
    </div>
  </section>
</template>
