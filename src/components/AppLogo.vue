<script setup lang="ts">
defineProps<{ compact?: boolean }>();
</script>

<template>
  <div class="brand" :class="{ 'brand--compact': compact }">
    <div class="brand__mark" aria-hidden="true">
      <svg viewBox="0 0 150 163">
        <path
          d="M139.7 19l-24 100.8s-37-10.5-50.5-15l44-53.6-61 48.2L7.5 86zm-74.2 97.3l15.4 5L65 145z"
          fill="currentColor"
        />
      </svg>
    </div>
    <div v-if="!compact" class="brand__text">
      <strong>Shadowsocks</strong>
    </div>
  </div>
</template>
