import { createRouter, createWebHashHistory } from "vue-router";
import ConnectionsView from "@/views/ConnectionsView.vue";
import LogsView from "@/views/LogsView.vue";
import OverviewView from "@/views/OverviewView.vue";
import RulesView from "@/views/RulesView.vue";
import ServersView from "@/views/ServersView.vue";
import SettingsView from "@/views/SettingsView.vue";
import SubscriptionsView from "@/views/SubscriptionsView.vue";
import TrafficView from "@/views/TrafficView.vue";

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", name: "overview", component: OverviewView },
    { path: "/servers", name: "servers", component: ServersView },
    {
      path: "/subscriptions",
      name: "subscriptions",
      component: SubscriptionsView,
    },
    { path: "/rules", name: "rules", component: RulesView },
    {
      path: "/connections",
      name: "connections",
      component: ConnectionsView,
    },
    { path: "/traffic", name: "traffic", component: TrafficView },
    { path: "/logs", name: "logs", component: LogsView },
    { path: "/settings", name: "settings", component: SettingsView },
  ],
});
