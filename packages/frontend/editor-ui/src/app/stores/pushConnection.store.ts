import { defineStore } from 'pinia';
import { computed, ref, watch } from 'vue';
import type { PushMessage } from '@n8n/api-types';

import { STORES } from '@n8n/stores';
import { useSettingsStore } from './settings.store';
import { useRootStore } from '@n8n/stores/useRootStore';
import { useWebSocketClient } from '@/app/push-connection/useWebSocketClient';
import { useEventSourceClient } from '@/app/push-connection/useEventSourceClient';
import { useLocalStorage } from '@vueuse/core';
import { LOCAL_STORAGE_RUN_DATA_WORKER } from '@/app/constants';
import { runDataWorker } from '@/app/workers/run-data/instance';

export type OnPushMessageHandler = (event: PushMessage) => void;

/**
 * Store for managing a push connection to the server
 */
export const usePushConnectionStore = defineStore(STORES.PUSH, () => {
	const rootStore = useRootStore();
	const settingsStore = useSettingsStore();

	const isRunDataWorkerEnabled = useLocalStorage<boolean>(LOCAL_STORAGE_RUN_DATA_WORKER, false);

	/**
	 * Queue of messages to be sent to the server. Messages are queued if
	 * the connection is down.
	 */
	const outgoingQueue = ref<unknown[]>([]);

	/** Whether the connection has been requested */
	const isConnectionRequested = ref(false);

	const onMessageReceivedHandlers = ref<OnPushMessageHandler[]>([]);

	const addEventListener = (handler: OnPushMessageHandler) => {
		onMessageReceivedHandlers.value.push(handler);

		return () => {
			const index = onMessageReceivedHandlers.value.indexOf(handler);
			if (index !== -1) {
				onMessageReceivedHandlers.value.splice(index, 1);
			}
		};
	};

	const useWebSockets = computed(() => settingsStore.pushBackend === 'websocket');

	const getConnectionUrl = () => {
		const restUrl = rootStore.restUrl;
		const url = `/push?pushRef=${rootStore.pushRef}`;

		console.log('[PushConnection] getConnectionUrl called:', {
			restUrl,
			pushRef: rootStore.pushRef,
			useWebSockets: useWebSockets.value,
			windowOrigin: typeof window !== 'undefined' ? window.location?.origin : 'N/A',
		});

		if (useWebSockets.value) {
			// Check if we're in VS Code webview context
			const isVSCodeWebview =
				typeof window !== 'undefined' && window.location?.origin?.startsWith('vscode-webview:');

			console.log('[PushConnection] WebSocket mode - isVSCodeWebview:', isVSCodeWebview);

			let baseUrl: string;

			if (restUrl.startsWith('http')) {
				// restUrl already has full URL, convert http(s) to ws(s)
				baseUrl = restUrl.replace(/^http/, 'ws');
				console.log('[PushConnection] Using restUrl with http prefix, converted to ws:', baseUrl);
			} else if (isVSCodeWebview) {
				// In VS Code webview, use __API_BASE_URL__ (injected by extension) if available
				const apiBaseUrl =
					(window as unknown as { __API_BASE_URL__?: string }).__API_BASE_URL__ ||
					'http://localhost:5888';
				console.log('[PushConnection] VS Code webview detected - __API_BASE_URL__:', apiBaseUrl);
				// Convert http(s) URL to ws(s) URL
				baseUrl = apiBaseUrl.replace(/^http/, 'ws') + restUrl;
				console.log('[PushConnection] Constructed WebSocket baseUrl from apiBaseUrl:', baseUrl);
			} else {
				// Standard browser context, use window.location
				const { protocol, host } = window.location;
				baseUrl = `${protocol === 'https:' ? 'wss' : 'ws'}://${host + restUrl}`;
				console.log('[PushConnection] Standard browser mode - using window.location:', {
					protocol,
					host,
					baseUrl,
				});
			}

			const finalUrl = `${baseUrl}${url}`;
			console.log('[PushConnection] Final WebSocket URL:', finalUrl);
			return finalUrl;
		} else {
			// EventSource path - also needs to handle VS Code webview context
			const isVSCodeWebview =
				typeof window !== 'undefined' && window.location?.origin?.startsWith('vscode-webview:');

			console.log('[PushConnection] EventSource mode - isVSCodeWebview:', isVSCodeWebview);

			let finalUrl: string;
			if (restUrl.startsWith('http')) {
				finalUrl = `${restUrl}${url}`;
				console.log('[PushConnection] EventSource using restUrl with http prefix:', finalUrl);
			} else if (isVSCodeWebview) {
				const apiBaseUrl =
					(window as unknown as { __API_BASE_URL__?: string }).__API_BASE_URL__ ||
					'http://localhost:5888';
				console.log('[PushConnection] VS Code webview detected - __API_BASE_URL__:', apiBaseUrl);
				finalUrl = `${apiBaseUrl}${restUrl}${url}`;
				console.log('[PushConnection] Constructed EventSource URL from apiBaseUrl:', finalUrl);
			} else {
				finalUrl = `${restUrl}${url}`;
				console.log('[PushConnection] Standard browser EventSource URL:', finalUrl);
			}
			return finalUrl;
		}
	};

	/**
	 * Process a newly received message
	 */
	async function onMessage(data: unknown) {
		// The `nodeExecuteAfterData` message is sent as binary data
		// to be handled by a web worker in the future.
		if (data instanceof ArrayBuffer) {
			if (isRunDataWorkerEnabled.value) {
				await runDataWorker.onNodeExecuteAfterData(data);
				return;
			} else {
				data = new TextDecoder('utf-8').decode(new Uint8Array(data));
			}
		}

		let parsedData: PushMessage;
		try {
			parsedData = JSON.parse(data as string);
		} catch (error) {
			return;
		}

		onMessageReceivedHandlers.value.forEach((handler) => handler(parsedData));
	}

	const url = getConnectionUrl();

	const client = computed(() =>
		useWebSockets.value
			? useWebSocketClient({ url, onMessage })
			: useEventSourceClient({ url, onMessage }),
	);

	function serializeAndSend(message: unknown) {
		if (client.value.isConnected.value) {
			client.value.sendMessage(JSON.stringify(message));
		} else {
			outgoingQueue.value.push(message);
		}
	}

	const pushConnect = () => {
		isConnectionRequested.value = true;
		client.value.connect();
	};

	const pushDisconnect = () => {
		isConnectionRequested.value = false;
		client.value.disconnect();
	};

	watch(
		() => client.value.isConnected.value,
		(didConnect) => {
			if (!didConnect) {
				return;
			}

			// Send any buffered messages
			if (outgoingQueue.value.length) {
				for (const message of outgoingQueue.value) {
					serializeAndSend(message);
				}
				outgoingQueue.value = [];
			}
		},
	);

	/** Removes all buffered messages from the sent queue */
	const clearQueue = () => {
		outgoingQueue.value = [];
	};

	const isConnected = computed(() => client.value.isConnected.value);

	return {
		isConnected,
		isConnectionRequested,
		onMessageReceivedHandlers,
		addEventListener,
		pushConnect,
		pushDisconnect,
		send: serializeAndSend,
		clearQueue,
	};
});
