<script setup lang="ts">
import { computed } from "vue";
import type { TrafficSample } from "@/domain/models";

const props = defineProps<{ samples: TrafficSample[] }>();

const downloadPoints = computed(() => makePoints("download"));
const uploadPoints = computed(() => makePoints("upload"));

function makePoints(field: "upload" | "download") {
  if (!props.samples.length) return "";
  const width = 620;
  const height = 170;
  const values = props.samples.map((sample) => sample[field]);
  const max = Math.max(...values, 1);
  return values
    .map((value, index) => {
      const x = (index / Math.max(values.length - 1, 1)) * width;
      const y = height - (value / max) * (height - 22) - 10;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}
</script>

<template>
  <svg class="sparkline" viewBox="0 0 620 180" preserveAspectRatio="none">
    <defs>
      <linearGradient id="download-fill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#5b8cff" stop-opacity=".28" />
        <stop offset="100%" stop-color="#5b8cff" stop-opacity="0" />
      </linearGradient>
    </defs>
    <path class="sparkline__grid" d="M0 45H620M0 90H620M0 135H620" />
    <polygon
      v-if="downloadPoints"
      :points="`0,180 ${downloadPoints} 620,180`"
      fill="url(#download-fill)"
    />
    <polyline
      :points="downloadPoints"
      fill="none"
      stroke="#5b8cff"
      stroke-width="3"
      vector-effect="non-scaling-stroke"
    />
    <polyline
      :points="uploadPoints"
      fill="none"
      stroke="#22c7a9"
      stroke-width="2"
      vector-effect="non-scaling-stroke"
    />
  </svg>
</template>
