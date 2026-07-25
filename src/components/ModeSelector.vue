<script setup lang="ts">
import type { ConnectionMode } from "@/domain/models";

defineProps<{ modelValue: ConnectionMode }>();
const emit = defineEmits<{ "update:modelValue": [value: ConnectionMode] }>();

const modes: Array<{ id: ConnectionMode; label: string }> = [
  { id: "direct", label: "直连" },
  { id: "rule", label: "规则" },
  { id: "global", label: "全局" },
];
</script>

<template>
  <div class="segmented-control" aria-label="连接模式">
    <button
      v-for="item in modes"
      :key="item.id"
      type="button"
      :class="{ active: modelValue === item.id }"
      @click="emit('update:modelValue', item.id)"
    >
      {{ item.label }}
    </button>
  </div>
</template>
