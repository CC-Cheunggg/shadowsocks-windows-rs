<script setup lang="ts">
import AppIcon from "@/components/AppIcon.vue";
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>订阅</h2>
        <p>集中管理节点来源，更新过程支持校验和失败回滚。</p>
      </div>
      <button class="primary-button" type="button">
        <AppIcon name="plus" :size="18" />添加订阅
      </button>
    </div>
    <article class="feature-placeholder surface-card">
      <span class="feature-placeholder__icon"><AppIcon name="subscriptions" :size="28" /></span>
      <div>
        <span class="card-kicker">下一里程碑</span>
        <h3>安全的在线配置</h3>
        <p>这里将提供 SIP008订阅、增量更新、分组同步和变更预览。</p>
      </div>
    </article>
  </section>
</template>
