import { randomString, setGlobalState } from 'n8n-workflow';
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

import { STORES } from './constants';
import { getConfigFromMetaTag } from './metaTagConfig';

export type RootStoreState = {
	baseUrl: string;
	restEndpoint: string;
	defaultLocale: string;
	endpointForm: string;
	endpointFormTest: string;
	endpointFormWaiting: string;
	endpointMcp: string;
	endpointMcpTest: string;
	endpointWebhook: string;
	endpointWebhookTest: string;
	endpointWebhookWaiting: string;
	timezone: string;
	executionTimeout: number;
	maxExecutionTimeout: number;
	versionCli: string;
	oauthCallbackUrls: object;
	n8nMetadata: {
		[key: string]: string | number | undefined;
	};
	pushRef: string;
	urlBaseWebhook: string;
	urlBaseEditor: string;
	instanceId: string;
	binaryDataMode: 'default' | 'filesystem' | 's3' | 'database';
};

// Helper function to get a valid base URL with fallbacks
function getBaseUrl(): string {
	const { VUE_APP_URL_BASE_API } = import.meta.env;
	const envUrl = VUE_APP_URL_BASE_API;
	const windowApiUrl = window.__API_BASE_URL__;
	const windowBasePath = window.BASE_PATH;

	// Try each option in order
	// Ignore envUrl if it is the unreplaced placeholder "{{BASE_PATH}}"
	const validEnvUrl = envUrl !== '{{BASE_PATH}}' ? envUrl : undefined;
	const url = validEnvUrl ?? windowApiUrl ?? windowBasePath;

	// If we have a valid URL, return it
	if (url && url.trim() !== '') {
		return url;
	}

	// Fallback: use current origin if available (for browser environments)
	// Skip if in VS Code webview (origin starts with 'vscode-webview:')
	if (
		typeof window !== 'undefined' &&
		window.location &&
		!window.location.origin.startsWith('vscode-webview:')
	) {
		return window.location.origin;
	}

	// Last resort: for VS Code webview, default to localhost
	return 'http://localhost:5678';
}

export const useRootStore = defineStore(STORES.ROOT, () => {
	const state = ref<RootStoreState>({
		baseUrl: getBaseUrl(),
		restEndpoint: getConfigFromMetaTag('rest-endpoint') ?? 'rest',
		defaultLocale: 'en',
		endpointForm: 'form',
		endpointFormTest: 'form-test',
		endpointFormWaiting: 'form-waiting',
		endpointMcp: 'mcp',
		endpointMcpTest: 'mcp-test',
		endpointWebhook: 'webhook',
		endpointWebhookTest: 'webhook-test',
		endpointWebhookWaiting: 'webhook-waiting',
		timezone: 'America/New_York',
		executionTimeout: -1,
		maxExecutionTimeout: Number.MAX_SAFE_INTEGER,
		versionCli: '0.0.0',
		oauthCallbackUrls: {},
		n8nMetadata: {},
		pushRef: randomString(10).toLowerCase(),
		urlBaseWebhook: 'http://localhost:5678/',
		urlBaseEditor: 'http://localhost:5678',
		instanceId: '',
		binaryDataMode: 'default',
	});

	// ---------------------------------------------------------------------------
	// #region Computed
	// ---------------------------------------------------------------------------

	const baseUrl = computed(() => state.value.baseUrl);

	const formUrl = computed(() => `${state.value.urlBaseWebhook}${state.value.endpointForm}`);

	const formTestUrl = computed(() => `${state.value.urlBaseEditor}${state.value.endpointFormTest}`);

	const formWaitingUrl = computed(
		() => `${state.value.urlBaseEditor}${state.value.endpointFormWaiting}`,
	);

	const webhookUrl = computed(() => `${state.value.urlBaseWebhook}${state.value.endpointWebhook}`);

	const webhookTestUrl = computed(
		() => `${state.value.urlBaseEditor}${state.value.endpointWebhookTest}`,
	);

	const webhookWaitingUrl = computed(
		() => `${state.value.urlBaseEditor}${state.value.endpointWebhookWaiting}`,
	);

	const mcpUrl = computed(() => `${state.value.urlBaseWebhook}${state.value.endpointMcp}`);

	const mcpTestUrl = computed(() => `${state.value.urlBaseEditor}${state.value.endpointMcpTest}`);

	const pushRef = computed(() => state.value.pushRef);

	const binaryDataMode = computed(() => state.value.binaryDataMode);

	const defaultLocale = computed(() => state.value.defaultLocale);

	const urlBaseEditor = computed(() => state.value.urlBaseEditor);

	const instanceId = computed(() => state.value.instanceId);

	const versionCli = computed(() => state.value.versionCli);

	const OAuthCallbackUrls = computed(() => state.value.oauthCallbackUrls);

	// Ensure restUrl is always a valid URL
	const restUrl = computed(() => {
		const base = state.value.baseUrl || '/';
		const endpoint = state.value.restEndpoint || 'rest';

		// Normalize base URL: remove trailing slash if present
		const normalizedBase = base.endsWith('/') ? base.slice(0, -1) : base;

		// Construct URL with proper separator
		return `${normalizedBase}/${endpoint}`;
	});

	const executionTimeout = computed(() => state.value.executionTimeout);

	const maxExecutionTimeout = computed(() => state.value.maxExecutionTimeout);

	const timezone = computed(() => state.value.timezone);

	const restApiContext = computed(() => ({
		baseUrl: restUrl.value,
		pushRef: state.value.pushRef,
	}));

	// #endregion

	// ---------------------------------------------------------------------------
	// #region Methods
	// ---------------------------------------------------------------------------

	const setUrlBaseWebhook = (value: string) => {
		const url = value.endsWith('/') ? value : `${value}/`;
		state.value.urlBaseWebhook = url;
	};

	const setUrlBaseEditor = (value: string) => {
		const url = value.endsWith('/') ? value : `${value}/`;
		state.value.urlBaseEditor = url;
	};

	const setEndpointForm = (value: string) => {
		state.value.endpointForm = value;
	};

	const setEndpointFormTest = (value: string) => {
		state.value.endpointFormTest = value;
	};

	const setEndpointFormWaiting = (value: string) => {
		state.value.endpointFormWaiting = value;
	};

	const setEndpointWebhook = (value: string) => {
		state.value.endpointWebhook = value;
	};

	const setEndpointWebhookTest = (value: string) => {
		state.value.endpointWebhookTest = value;
	};

	const setEndpointWebhookWaiting = (value: string) => {
		state.value.endpointWebhookWaiting = value;
	};

	const setEndpointMcp = (value: string) => {
		state.value.endpointMcp = value;
	};

	const setEndpointMcpTest = (value: string) => {
		state.value.endpointMcpTest = value;
	};

	const setTimezone = (value: string) => {
		state.value.timezone = value;
		setGlobalState({ defaultTimezone: value });
	};

	const setExecutionTimeout = (value: number) => {
		state.value.executionTimeout = value;
	};

	const setMaxExecutionTimeout = (value: number) => {
		state.value.maxExecutionTimeout = value;
	};

	const setVersionCli = (value: string) => {
		state.value.versionCli = value;
	};

	const setInstanceId = (value: string) => {
		state.value.instanceId = value;
	};

	const setOauthCallbackUrls = (value: RootStoreState['oauthCallbackUrls']) => {
		state.value.oauthCallbackUrls = value;
	};

	const setN8nMetadata = (value: RootStoreState['n8nMetadata']) => {
		state.value.n8nMetadata = value;
	};

	const setDefaultLocale = (value: string) => {
		state.value.defaultLocale = value;
	};

	const setBinaryDataMode = (value: RootStoreState['binaryDataMode']) => {
		state.value.binaryDataMode = value;
	};

	// #endregion

	return {
		baseUrl,
		formUrl,
		formTestUrl,
		formWaitingUrl,
		mcpUrl,
		mcpTestUrl,
		webhookUrl,
		webhookTestUrl,
		webhookWaitingUrl,
		restUrl,
		restApiContext,
		urlBaseEditor,
		versionCli,
		instanceId,
		pushRef,
		defaultLocale,
		binaryDataMode,
		OAuthCallbackUrls,
		executionTimeout,
		maxExecutionTimeout,
		timezone,
		setUrlBaseWebhook,
		setUrlBaseEditor,
		setEndpointForm,
		setEndpointFormTest,
		setEndpointFormWaiting,
		setEndpointWebhook,
		setEndpointWebhookTest,
		setEndpointWebhookWaiting,
		setEndpointMcp,
		setEndpointMcpTest,
		setTimezone,
		setExecutionTimeout,
		setMaxExecutionTimeout,
		setVersionCli,
		setInstanceId,
		setOauthCallbackUrls,
		setN8nMetadata,
		setDefaultLocale,
		setBinaryDataMode,
	};
});
