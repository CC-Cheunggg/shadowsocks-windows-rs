<script setup lang="ts">
import AppIcon from "@/components/AppIcon.vue";
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div><h2>路由规则</h2><p>定义哪些连接直连、代理或阻断。</p></div>
      <button class="primary-button" type="button"><AppIcon name="plus" :size="18" />新建规则</button>
    </div>
    <div class="rule-preview-grid">
      <article class="surface-card rule-card">
        <span class="rule-card__tone rule-card__tone--green">DIRECT</span>
        <h3>局域网与专用地址</h3>
        <p>自动绕过网关、DHCP和 RFC专用地址。</p>
        <strong>18条规则</strong>
      </article>
      <article class="surface-card rule-card">
        <span class="rule-card__tone rule-card__tone--blue">PROXY</span>
        <h3>GeoSite代理规则</h3>
        <p>按域名分类将流量发送到安全隧道。</p>
        <strong>规则集待接入</strong>
      </article>
      <article class="surface-card rule-card">
        <span class="rule-card__tone rule-card__tone--orange">FINAL</span>
        <h3>最终策略</h3>
        <p>未命中连接遵循当前的规则模式配置。</p>
        <strong>代理</strong>
      </article>
    </div>
  </section>
</template>
