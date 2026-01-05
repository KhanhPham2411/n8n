import { watch, computed } from 'vue';
import { useWorkflowsStore } from '@/app/stores/workflows.store';
import { useUIStore } from '@/app/stores/ui.store';
import { debounce } from 'lodash-es';
import type { IWorkflowDb } from '@/Interface';

/**
 * Check if running inside a VS Code webview
 */
export function isVSCodeWebview(): boolean {
	return typeof window !== 'undefined' && window.location?.origin?.startsWith('vscode-webview:');
}

/**
 * Workflow data to sync to the .n8n file
 */
export interface WorkflowFileData {
	name: string;
	nodes: IWorkflowDb['nodes'];
	connections: IWorkflowDb['connections'];
	settings?: IWorkflowDb['settings'];
	pinData?: IWorkflowDb['pinData'];
}

/**
 * Composable for syncing workflow changes back to the VS Code extension
 * This enables bidirectional sync: when the user saves a workflow in the UI,
 * the changes are sent to VS Code to update the .n8n file
 */
export function useWorkflowFileSync() {
	const workflowsStore = useWorkflowsStore();
	const uiStore = useUIStore();

	/**
	 * Serialize workflow data to ensure it's postMessage-safe
	 * This removes any non-serializable properties (functions, circular refs, etc.)
	 */
	function serializeWorkflowData(workflowData: WorkflowFileData): WorkflowFileData {
		try {
			// First, try to serialize without pinData (pinData can be large and problematic)
			const dataToSerialize: any = {
				name: workflowData.name,
				nodes: workflowData.nodes,
				connections: workflowData.connections,
				settings: workflowData.settings,
			};

			// Try to include pinData, but exclude it if it causes issues
			if (workflowData.pinData) {
				try {
					// Test if pinData can be serialized
					JSON.stringify(workflowData.pinData);
					dataToSerialize.pinData = workflowData.pinData;
				} catch (pinDataError) {
					console.warn(
						'[WorkflowFileSync] pinData cannot be serialized, excluding it:',
						pinDataError,
					);
					// Exclude pinData if it can't be serialized
				}
			}

			// Use JSON.stringify/parse to ensure data is serializable
			// This removes any non-serializable properties
			const serialized = JSON.parse(JSON.stringify(dataToSerialize));
			return serialized;
		} catch (error) {
			console.error('[WorkflowFileSync] Failed to serialize workflow data:', error);
			// Fallback: return minimal data without pinData
			try {
				return JSON.parse(
					JSON.stringify({
						name: workflowData.name,
						nodes: workflowData.nodes || [],
						connections: workflowData.connections || {},
						settings: workflowData.settings,
					}),
				);
			} catch (fallbackError) {
				console.error('[WorkflowFileSync] Fallback serialization also failed:', fallbackError);
				// Last resort: return minimal safe data
				return {
					name: workflowData.name || '',
					nodes: [],
					connections: {},
				};
			}
		}
	}

	/**
	 * Send workflow data to VS Code extension to update the .n8n file
	 * Only works when running inside a VS Code webview
	 * @param workflowData - The workflow data to sync
	 * @param shouldSave - If true, actually save the file; if false, just apply edit
	 * @param executionData - Optional execution data (runData) to save to .data file
	 * @param executionTiming - Optional execution timing information (startedAt, stoppedAt) for timestamped .data file
	 */
	function syncWorkflowToFile(
		workflowData: WorkflowFileData,
		shouldSave = false,
		executionData?: any,
		executionTiming?: { startedAt?: Date | string; stoppedAt?: Date | string },
	): void {
		if (!isVSCodeWebview()) {
			return;
		}

		// Get the VS Code API from the global window object (set in index.html)
		const vscode = (window as unknown as { vscode?: { postMessage: (msg: unknown) => void } })
			.vscode;
		if (!vscode || typeof vscode.postMessage !== 'function') {
			console.log('[WorkflowFileSync] VS Code API not available, skipping sync');
			return;
		}

		try {
			// Serialize the workflow data to ensure it's postMessage-safe
			const serializedWorkflow = serializeWorkflowData(workflowData);

			// Serialize execution data if provided
			let serializedExecutionData: any = undefined;
			if (executionData) {
				try {
					serializedExecutionData = JSON.parse(JSON.stringify(executionData));
				} catch (error) {
					console.warn('[WorkflowFileSync] Failed to serialize execution data:', error);
				}
			}

			// Serialize execution timing if provided
			let serializedExecutionTiming: any = undefined;
			if (executionTiming) {
				try {
					serializedExecutionTiming = {
						startedAt:
							executionTiming.startedAt instanceof Date
								? executionTiming.startedAt.toISOString()
								: executionTiming.startedAt,
						stoppedAt:
							executionTiming.stoppedAt instanceof Date
								? executionTiming.stoppedAt.toISOString()
								: executionTiming.stoppedAt,
					};
				} catch (error) {
					console.warn('[WorkflowFileSync] Failed to serialize execution timing:', error);
				}
			}

			// Create the message object
			const message: any = {
				type: 'workflowUpdate',
				workflow: serializedWorkflow,
				shouldSave, // Flag to indicate if this should save the file or just apply edit
			};

			// Include execution data if provided
			if (serializedExecutionData) {
				message.executionData = serializedExecutionData;
			}

			// Include execution timing if provided
			if (serializedExecutionTiming) {
				message.executionTiming = serializedExecutionTiming;
			}

			// Verify the message can be cloned before sending
			try {
				// Test if the message can be cloned (this will throw if it can't)
				structuredClone(message);
			} catch (cloneError) {
				console.error(
					'[WorkflowFileSync] Message cannot be cloned, attempting to fix by re-serializing:',
					cloneError,
				);
				// Try one more time with JSON round-trip
				const reSerialized = JSON.parse(JSON.stringify(message));
				vscode.postMessage(reSerialized);
				console.log(
					`[WorkflowFileSync] Sent workflow update to VS Code (re-serialized): ${workflowData.name} (shouldSave: ${shouldSave})`,
				);
				return;
			}

			// Send message to VS Code extension via the VS Code API
			vscode.postMessage(message);
			console.log(
				`[WorkflowFileSync] Sent workflow update to VS Code: ${workflowData.name} (shouldSave: ${shouldSave})`,
			);
		} catch (error) {
			console.error('[WorkflowFileSync] Failed to send workflow update:', error);
			// Log additional details for debugging
			if (error instanceof Error) {
				console.error('[WorkflowFileSync] Error details:', {
					name: error.name,
					message: error.message,
					stack: error.stack,
				});
			}
		}
	}

	/**
	 * Sync workflow from IWorkflowDb type
	 * @param workflow - The workflow to sync
	 * @param shouldSave - If true, actually save the file; if false, just apply edit
	 * @param executionData - Optional execution data (runData) to save to .data file
	 * @param executionTiming - Optional execution timing information (startedAt, stoppedAt) for timestamped .data file
	 */
	function syncFromWorkflowDb(
		workflow: IWorkflowDb,
		shouldSave = false,
		executionData?: any,
		executionTiming?: { startedAt?: Date | string; stoppedAt?: Date | string },
	): void {
		syncWorkflowToFile(
			{
				name: workflow.name,
				nodes: workflow.nodes,
				connections: workflow.connections,
				settings: workflow.settings,
				pinData: workflow.pinData,
			},
			shouldSave,
			executionData,
			executionTiming,
		);
	}

	/**
	 * Get current workflow data for syncing
	 */
	function getCurrentWorkflowData(): WorkflowFileData | null {
		const workflow = workflowsStore.workflow;
		if (!workflow || !workflow.name) {
			return null;
		}

		return {
			name: workflow.name,
			nodes: workflow.nodes,
			connections: workflow.connections,
			settings: workflow.settings,
			pinData: workflow.pinData,
		};
	}

	/**
	 * Debounced function to sync workflow changes automatically (apply edit)
	 * This is called when user makes edits in the UI
	 */
	const debouncedSyncWorkflow = debounce(() => {
		const workflowData = getCurrentWorkflowData();
		if (workflowData) {
			// Apply edit (not save) when user makes changes
			syncWorkflowToFile(workflowData, false);
		}
	}, 300); // Debounce for 300ms to avoid too many updates

	/**
	 * Watch for workflow changes and automatically sync (apply edit)
	 * This enables real-time sync when user edits in the UI
	 */
	function setupAutoSync() {
		if (!isVSCodeWebview()) {
			return;
		}

		// Watch for workflow changes (nodes, connections, name, etc.)
		const workflowData = computed(() => {
			const workflow = workflowsStore.workflow;
			return {
				name: workflow.name,
				nodes: workflow.nodes,
				connections: workflow.connections,
				settings: workflow.settings,
				pinData: workflow.pinData,
			};
		});

		let lastSyncedData: string | null = null;

		// Watch for workflow data changes and stateIsDirty
		watch(
			[workflowData, () => uiStore.stateIsDirty],
			([newWorkflowData, isDirty]) => {
				// Only sync if state is dirty (user made edits) and workflow has a name
				if (!isDirty || !newWorkflowData.name) {
					return;
				}

				// Serialize current workflow data to compare
				const currentDataString = JSON.stringify({
					nodes: newWorkflowData.nodes,
					connections: newWorkflowData.connections,
					name: newWorkflowData.name,
					settings: newWorkflowData.settings,
				});

				// Only sync if data actually changed
				if (currentDataString !== lastSyncedData) {
					lastSyncedData = currentDataString;
					debouncedSyncWorkflow();
				}
			},
			{ deep: true, immediate: false },
		);
	}

	/**
	 * Request loading the .data file associated with the current workflow
	 * Only works when running inside a VS Code webview
	 * @param filePath - Optional specific file path to load. If not provided, loads the default .data file
	 */
	function requestLoadDataFile(filePath?: string): Promise<void> {
		return new Promise((resolve, reject) => {
			if (!isVSCodeWebview()) {
				reject(new Error('Load data is only available in VS Code'));
				return;
			}

			// Get the VS Code API from the global window object (set in index.html)
			const vscode = (window as unknown as { vscode?: { postMessage: (msg: unknown) => void } })
				.vscode;
			if (!vscode || typeof vscode.postMessage !== 'function') {
				reject(new Error('VS Code API not available'));
				return;
			}

			try {
				const message: any = {
					type: 'loadDataFile',
				};

				if (filePath) {
					message.filePath = filePath;
				}

				// Set up a one-time listener for the response
				const messageHandler = (event: MessageEvent) => {
					if (event.data.type === 'dataFileLoaded') {
						window.removeEventListener('message', messageHandler);
						resolve();
					} else if (event.data.type === 'dataFileError') {
						window.removeEventListener('message', messageHandler);
						reject(new Error(event.data.error || 'Failed to load data file'));
					}
				};

				window.addEventListener('message', messageHandler);

				// Send message to VS Code extension via the VS Code API
				vscode.postMessage(message);
				console.log(
					'[WorkflowFileSync] Sent load data file request to VS Code',
					filePath ? `(path: ${filePath})` : '',
				);
			} catch (error) {
				console.error('[WorkflowFileSync] Failed to send load data file request:', error);
				reject(error);
			}
		});
	}

	/**
	 * Request listing all .data files associated with the current workflow
	 * Files matching pattern "%file%.data" where %file% is the base name of the .n8n file
	 * Only works when running inside a VS Code webview
	 */
	function requestListDataFiles(): Promise<Array<{ path: string; name: string }>> {
		return new Promise((resolve, reject) => {
			if (!isVSCodeWebview()) {
				reject(new Error('List data files is only available in VS Code'));
				return;
			}

			// Get the VS Code API from the global window object (set in index.html)
			const vscode = (window as unknown as { vscode?: { postMessage: (msg: unknown) => void } })
				.vscode;
			if (!vscode || typeof vscode.postMessage !== 'function') {
				reject(new Error('VS Code API not available'));
				return;
			}

			try {
				const message = {
					type: 'listDataFiles',
				};

				// Set up a one-time listener for the response
				const messageHandler = (event: MessageEvent) => {
					if (event.data.type === 'dataFileList') {
						window.removeEventListener('message', messageHandler);
						resolve(event.data.files || []);
					} else if (event.data.type === 'dataFileListError') {
						window.removeEventListener('message', messageHandler);
						reject(new Error(event.data.error || 'Failed to list data files'));
					}
				};

				window.addEventListener('message', messageHandler);

				// Send message to VS Code extension via the VS Code API
				vscode.postMessage(message);
				console.log('[WorkflowFileSync] Sent list data files request to VS Code');
			} catch (error) {
				console.error('[WorkflowFileSync] Failed to send list data files request:', error);
				reject(error);
			}
		});
	}

	return {
		isVSCodeWebview,
		syncWorkflowToFile,
		syncFromWorkflowDb,
		setupAutoSync,
		getCurrentWorkflowData,
		requestLoadDataFile,
		requestListDataFiles,
	};
}
