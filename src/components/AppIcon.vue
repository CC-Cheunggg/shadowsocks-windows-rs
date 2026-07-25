<script setup lang="ts">
defineProps<{
  name:
    | "overview"
    | "servers"
    | "subscriptions"
    | "rules"
    | "connections"
    | "traffic"
    | "logs"
    | "settings"
    | "shield"
    | "chevron"
    | "plus"
    | "search"
    | "more"
    | "check";
  size?: number;
}>();
</script>

<template>
  <svg
    :width="size ?? 20"
    :height="size ?? 20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.8"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <template v-if="name === 'overview'">
      <rect x="3" y="3" width="7" height="7" rx="2" />
      <rect x="14" y="3" width="7" height="7" rx="2" />
      <rect x="3" y="14" width="7" height="7" rx="2" />
      <path d="M14 17.5h7M17.5 14v7" />
    </template>
    <template v-else-if="name === 'servers'">
      <rect x="4" y="3" width="16" height="6" rx="2" />
      <rect x="4" y="15" width="16" height="6" rx="2" />
      <path d="M8 6h.01M8 18h.01M12 6h5M12 18h5" />
    </template>
    <template v-else-if="name === 'subscriptions'">
      <path d="M5 8a11 11 0 0 1 11 11M5 13a6 6 0 0 1 6 6" />
      <circle cx="5" cy="19" r="1" />
      <path d="M17 4h3v3M20 4l-5 5" />
    </template>
    <template v-else-if="name === 'rules'">
      <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="8" cy="17" r="2" />
    </template>
    <template v-else-if="name === 'connections'">
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="18" cy="18" r="3" />
      <path d="m8.5 10.5 7-3M8.5 13.5l7 3" />
    </template>
    <template v-else-if="name === 'traffic'">
      <path d="M4 19V9M10 19V4M16 19v-7M22 19H2" />
    </template>
    <template v-else-if="name === 'logs'">
      <path d="M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h7" />
    </template>
    <template v-else-if="name === 'settings'">
      <circle cx="12" cy="12" r="3" />
      <path d="M19 13.5v-3l-2-.7a7 7 0 0 0-.7-1.7l.9-1.9-2.1-2.1-1.9.9a7 7 0 0 0-1.7-.7L10.5 2h-3l-.7 2a7 7 0 0 0-1.7.7l-1.9-.9-2.1 2.1.9 1.9a7 7 0 0 0-.7 1.7L0 10.5v3l2 .7a7 7 0 0 0 .7 1.7l-.9 1.9 2.1 2.1 1.9-.9a7 7 0 0 0 1.7.7l.7 2h3l.7-2a7 7 0 0 0 1.7-.7l1.9.9 2.1-2.1-.9-1.9a7 7 0 0 0 .7-1.7z" transform="translate(2.5)" />
    </template>
    <template v-else-if="name === 'shield'">
      <path d="M12 3 20 6v5c0 5.1-3.3 8.6-8 10-4.7-1.4-8-4.9-8-10V6z" />
      <path d="m8.5 12 2.2 2.2 4.8-5" />
    </template>
    <path v-else-if="name === 'chevron'" d="m9 18 6-6-6-6" />
    <path v-else-if="name === 'plus'" d="M12 5v14M5 12h14" />
    <template v-else-if="name === 'search'">
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-4-4" />
    </template>
    <template v-else-if="name === 'more'">
      <circle cx="5" cy="12" r="1" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
      <circle cx="19" cy="12" r="1" fill="currentColor" stroke="none" />
    </template>
    <path v-else-if="name === 'check'" d="m5 12 4 4L19 6" />
  </svg>
</template>
