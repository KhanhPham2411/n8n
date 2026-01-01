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
	 */
	function syncWorkflowToFile(workflowData: WorkflowFileData, shouldSave = false): void {
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

			// Create the message object
			const message = {
				type: 'workflowUpdate',
				workflow: serializedWorkflow,
				shouldSave, // Flag to indicate if this should save the file or just apply edit
			};

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
	 */
	function syncFromWorkflowDb(workflow: IWorkflowDb, shouldSave = false): void {
		syncWorkflowToFile(
			{
				name: workflow.name,
				nodes: workflow.nodes,
				connections: workflow.connections,
				settings: workflow.settings,
				pinData: workflow.pinData,
			},
			shouldSave,
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

	return {
		isVSCodeWebview,
		syncWorkflowToFile,
		syncFromWorkflowDb,
		setupAutoSync,
		getCurrentWorkflowData,
	};
}
