<script setup lang="ts">
import AssistantsHub from '@/features/ai/assistant/components/AssistantsHub.vue';
import AskAssistantFloatingButton from '@/features/ai/assistant/components/Chat/AskAssistantFloatingButton.vue';
import BannerStack from '@/features/shared/banners/components/BannerStack.vue';
import Modals from '@/app/components/Modals.vue';
import { useHistoryHelper } from '@/app/composables/useHistoryHelper';
import { useTelemetryContext } from '@/app/composables/useTelemetryContext';
import { useTelemetryInitializer } from '@/app/composables/useTelemetryInitializer';
import { useWorkflowDiffRouting } from '@/app/composables/useWorkflowDiffRouting';
import {
	APP_MODALS_ELEMENT_ID,
	CODEMIRROR_TOOLTIP_CONTAINER_ELEMENT_ID,
	HIRING_BANNER,
	VIEWS,
} from '@/app/constants';
import { useChatPanelStore } from '@/features/ai/assistant/chatPanel.store';
import { useAssistantStore } from '@/features/ai/assistant/assistant.store';
import { useNDVStore } from '@/features/ndv/shared/ndv.store';
import { useSettingsStore } from '@/app/stores/settings.store';
import { useUIStore } from '@/app/stores/ui.store';
import { useUsersStore } from '@/features/settings/users/users.store';
import LoadingView from '@/app/views/LoadingView.vue';
import { locale, N8nCommandBar } from '@n8n/design-system';
import { setLanguage } from '@n8n/i18n';
// Note: no need to import en.json here; default 'en' is handled via setLanguage
import { useRootStore } from '@n8n/stores/useRootStore';
import axios from 'axios';
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { useStyles } from '@/app/composables/useStyles';
import { useExposeCssVar } from '@/app/composables/useExposeCssVar';
import { useFloatingUiOffsets } from '@/app/composables/useFloatingUiOffsets';
import { useCommandBar } from '@/features/shared/commandBar/composables/useCommandBar';
import { hasPermission } from '@/app/utils/rbac/permissions';
import { useWorkflowSync } from '@/app/composables/useWorkflowSync';
import { useToast } from '@/app/composables/useToast';
import { useCanvasOperations } from '@/app/composables/useCanvasOperations';
import { useWorkflowsStore } from '@/app/stores/workflows.store';
import { useExecutionDebugging } from '@/features/execution/executions/composables/useExecutionDebugging';

const route = useRoute();
const rootStore = useRootStore();
const assistantStore = useAssistantStore();
const chatPanelStore = useChatPanelStore();
const uiStore = useUIStore();
const usersStore = useUsersStore();
const settingsStore = useSettingsStore();
const ndvStore = useNDVStore();
const { APP_Z_INDEXES } = useStyles();

const {
	initialize: initializeCommandBar,
	isEnabled: isCommandBarEnabled,
	items,
	placeholder,
	context,
	onCommandBarChange,
	onCommandBarNavigateTo,
	isLoading: isCommandBarLoading,
} = useCommandBar();

const { setAppZIndexes } = useStyles();
const { toastBottomOffset, askAiFloatingButtonBottomOffset } = useFloatingUiOffsets();

// Initialize undo/redo
useHistoryHelper(route);

// Initialize workflow diff routing management
useWorkflowDiffRouting();

useTelemetryInitializer();

const loading = ref(true);
const defaultLocale = computed(() => rootStore.defaultLocale);
const isDemoMode = computed(() => route.name === VIEWS.DEMO);
const hasContentFooter = ref(false);
const appGrid = ref<Element | null>(null);

const showCommandBar = computed(
	() => isCommandBarEnabled.value && hasPermission(['authenticated']) && !isDemoMode.value,
);

const chatPanelWidth = computed(() => chatPanelStore.width);

useTelemetryContext({ ndv_source: computed(() => ndvStore.lastSetActiveNodeSource) });

// Global message handler for VS Code workflowSync messages
const toast = useToast();
const { applyRunDataFromFile } = useExecutionDebugging();

async function handleVSCodeWorkflowSync(messageEvent: MessageEvent) {
	// Handle object-based messages from VS Code webview
	if (typeof messageEvent.data === 'object' && messageEvent.data !== null) {
		if (messageEvent.data.type === 'workflowSync') {
			console.log('[App.vue] Received workflowSync message');
			try {
				const { syncWorkflow, navigateToWorkflow } = useWorkflowSync();
				const { initializeWorkspace } = useCanvasOperations();
				const workflowsStore = useWorkflowsStore();
				const workflowData = messageEvent.data.workflow;

				if (!workflowData || !workflowData.name) {
					throw new Error('Invalid workflow data: missing name');
				}

				console.log('[App.vue] Syncing workflow:', workflowData.name);
				const result = await syncWorkflow(workflowData);

				// Navigate to the workflow only if we're not already on it or if it's a new workflow
				// This prevents closing the NDV when syncing after node execution
				if (result.action === 'created' || workflowsStore.workflowId !== result.workflow.id) {
					await navigateToWorkflow(result.workflow.id);
				}

				// Refresh the workflow data in the UI by fetching and initializing workspace
				try {
					const updatedWorkflow = await workflowsStore.fetchWorkflow(result.workflow.id);
					if (updatedWorkflow.checksum) {
						// Check if we're currently viewing this workflow
						if (workflowsStore.workflowId === result.workflow.id) {
							await initializeWorkspace(updatedWorkflow);
							console.log('[App.vue] Workflow UI refreshed');
						}
					}
				} catch (refreshError) {
					console.warn('[App.vue] Failed to refresh workflow UI:', refreshError);
					// Don't throw - sync was successful, refresh is just a nice-to-have
				}

				// Notify VS Code that sync completed
				if (window.parent) {
					window.parent.postMessage(
						JSON.stringify({
							command: 'workflowSyncComplete',
							workflowId: result.workflow.id,
							workflowName: result.workflow.name,
							action: result.action,
						}),
						'*',
					);
				}

				// Show toast message only for new workflow creation
				if (result.action === 'created') {
					toast.showMessage({
						title: 'Workflow Created',
						message: `Created new workflow: ${result.workflow.name}`,
						type: 'success',
					});
				}
			} catch (e) {
				console.error('[App.vue] Workflow sync error:', e);
				if (window.top) {
					window.top.postMessage(
						JSON.stringify({
							command: 'error',
							message: 'Failed to sync workflow',
							error: (e as Error).message,
						}),
						'*',
					);
				}
				toast.showError(e, 'Workflow Sync Error');
			}
		} else if (messageEvent.data.type === 'dataFileLoaded') {
			console.log('[App.vue] Received dataFileLoaded message');
			try {
				const runData = messageEvent.data.runData;

				if (!runData) {
					throw new Error('No runData provided in dataFileLoaded message');
				}

				await applyRunDataFromFile(runData);
				console.log('[App.vue] Applied runData from file');
			} catch (e) {
				console.error('[App.vue] Failed to apply data from file:', e);
				toast.showError(e, 'Failed to load data from file');
			}
		} else if (messageEvent.data.type === 'dataFileError') {
			console.error('[App.vue] Data file error:', messageEvent.data.error);
			toast.showError(
				new Error(messageEvent.data.error || 'Failed to load data file'),
				'Data file error',
			);
		}
	}
}

onMounted(async () => {
	setAppZIndexes();
	logHiringBanner();
	loading.value = false;
	window.addEventListener('resize', updateGridWidth);
	window.addEventListener('message', handleVSCodeWorkflowSync);
	await updateGridWidth();
});

watch(showCommandBar, (newVal) => {
	if (newVal) {
		void initializeCommandBar();
	}
});

onBeforeUnmount(() => {
	window.removeEventListener('resize', updateGridWidth);
	window.removeEventListener('message', handleVSCodeWorkflowSync);
});

const logHiringBanner = () => {
	if (settingsStore.isHiringBannerEnabled && !isDemoMode.value) {
		console.log(HIRING_BANNER);
	}
};

const updateGridWidth = async () => {
	await nextTick();
	if (appGrid.value) {
		const { width, height } = appGrid.value.getBoundingClientRect();
		uiStore.appGridDimensions = { width, height };
	}
};
// As chat panel width changes, recalculate the total width regularly
watch(chatPanelWidth, async () => {
	await updateGridWidth();
});

watch(route, (r) => {
	hasContentFooter.value = r.matched.some(
		(matchedRoute) => matchedRoute.components?.footer !== undefined,
	);
});

watch(
	defaultLocale,
	async (newLocale) => {
		setLanguage(newLocale);

		axios.defaults.headers.common['Accept-Language'] = newLocale;

		void locale.use(newLocale);
	},
	{ immediate: true },
);

useExposeCssVar('--toast--offset', toastBottomOffset);
useExposeCssVar('--ask-assistant--floating-button--margin-bottom', askAiFloatingButtonBottomOffset);
</script>

<template>
	<LoadingView v-if="loading" />
	<div
		v-else
		id="n8n-app"
		:class="{
			[$style.container]: true,
			[$style.sidebarCollapsed]: uiStore.sidebarMenuCollapsed,
		}"
	>
		<div id="app-grid" ref="appGrid" :class="$style['app-grid']">
			<div id="banners" :class="$style.banners">
				<BannerStack v-if="!isDemoMode" />
			</div>
			<div id="header" :class="$style.header">
				<RouterView name="header" />
			</div>
			<div v-if="usersStore.currentUser" id="sidebar" :class="$style.sidebar">
				<RouterView name="sidebar" />
			</div>
			<div id="content" :class="$style.content">
				<div :class="$style.contentWrapper">
					<RouterView v-slot="{ Component }">
						<KeepAlive v-if="$route.meta.keepWorkflowAlive" include="NodeView" :max="1">
							<component :is="Component" />
						</KeepAlive>
						<component :is="Component" v-else />
					</RouterView>
				</div>
				<div v-if="hasContentFooter" :class="$style.contentFooter">
					<RouterView name="footer" />
				</div>
			</div>
			<div :id="APP_MODALS_ELEMENT_ID" :class="$style.modals">
				<Modals />
			</div>

			<N8nCommandBar
				v-if="showCommandBar"
				:items="items"
				:placeholder="placeholder"
				:context="context"
				:is-loading="isCommandBarLoading"
				:z-index="APP_Z_INDEXES.COMMAND_BAR"
				@input-change="onCommandBarChange"
				@navigate-to="onCommandBarNavigateTo"
			/>
			<AskAssistantFloatingButton v-if="assistantStore.isFloatingButtonShown" />
		</div>
		<AssistantsHub />
		<div :id="CODEMIRROR_TOOLTIP_CONTAINER_ELEMENT_ID" />
	</div>
</template>

<style lang="scss" module>
// On the root level, whole app is a flex container
// with app grid and assistant sidebar as children
.container {
	height: 100vh;
	overflow: hidden;
	display: grid;
	grid-template-columns: 1fr auto;
}

// App grid is the main app layout including modals and other absolute positioned elements
.app-grid {
	position: relative;
	display: grid;
	height: 100vh;
	grid-template-areas:
		'banners banners'
		'sidebar header'
		'sidebar content';
	grid-template-columns: auto 1fr;
	grid-template-rows: auto auto 1fr;
}

.banners {
	grid-area: banners;
	z-index: var(--top-banners--z);
}

.content {
	display: flex;
	flex-direction: column;
	align-items: center;
	overflow: auto;
	grid-area: content;
}

.contentFooter {
	height: auto;
	z-index: 10;
	width: 100%;
	display: none;

	// Only show footer if there's content
	&:has(*) {
		display: block;
	}
}

.contentWrapper {
	display: flex;
	grid-area: content;
	position: relative;
	overflow: auto;
	height: 100%;
	width: 100%;
	justify-content: center;

	main {
		width: 100%;
		height: 100%;
	}
}

.header {
	grid-area: header;
	z-index: var(--app-header--z);
	min-width: 0;
	min-height: 0;
}

.sidebar {
	grid-area: sidebar;
	z-index: var(--app-sidebar--z);
}

.modals {
	width: 100%;
}
</style>
