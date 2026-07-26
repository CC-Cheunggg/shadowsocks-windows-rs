<script setup lang="ts">
import { computed } from "vue";
import { useAppStore } from "@/stores/app";

const app = useAppStore();
const enabledRules = computed(
  () => app.config?.routing.rules.filter((rule) => rule.enabled) ?? [],
);
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>路由规则</h2>
        <p>规则按配置顺序确定性匹配；当前切片只实现 DIRECT outbound。</p>
      </div>
    </div>
    <div class="rule-preview-grid">
      <article class="surface-card rule-card">
        <span class="rule-card__tone rule-card__tone--green">DIRECT</span>
        <h3>已实现</h3>
        <p>仍先经过 Wintun、session 与 router，再由绑定物理接口的原生 socket 出站。</p>
        <strong>{{ app.runtime.counters.routeDirect }} 次决策</strong>
      </article>
      <article class="surface-card rule-card">
        <span class="rule-card__tone rule-card__tone--blue">PROXY</span>
        <h3>本轮未实现</h3>
        <p>命中 PROXY 会明确失败并安全丢弃，不会静默回退到 DIRECT。</p>
        <strong>{{ app.runtime.counters.routeProxy }} 次决策</strong>
      </article>
      <article class="surface-card rule-card">
        <span class="rule-card__tone rule-card__tone--orange">FINAL</span>
        <h3>规则默认动作</h3>
        <p>未命中有序规则时使用配置中的 default_action。</p>
        <strong>{{ app.config?.routing.default_action?.toUpperCase() ?? "PROXY" }}</strong>
      </article>
    </div>

    <article class="surface-card ordered-rules">
      <div class="ordered-rules__header">
        <div>
          <span class="card-kicker">确定性优先级</span>
          <h3>已启用规则</h3>
        </div>
        <strong>{{ enabledRules.length }} 条</strong>
      </div>
      <div v-if="enabledRules.length" class="ordered-rules__list">
        <div v-for="(rule, index) in enabledRules" :key="rule.id">
          <span>{{ index + 1 }}</span>
          <code>{{ rule.match_type }}</code>
          <strong>{{ rule.value }}</strong>
          <em :class="{ 'route-direct': rule.action === 'direct' }">
            {{ rule.action.toUpperCase() }}
          </em>
        </div>
      </div>
      <p v-else>
        当前没有已启用规则；rule 模式将直接使用
        {{ app.config?.routing.default_action?.toUpperCase() ?? "PROXY" }}。
      </p>
    </article>
  </section>
</template>
