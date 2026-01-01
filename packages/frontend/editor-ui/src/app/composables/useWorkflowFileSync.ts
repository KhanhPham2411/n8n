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
	/**
	 * Send workflow data to VS Code extension to update the .n8n file
	 * Only works when running inside a VS Code webview
	 */
	function syncWorkflowToFile(workflowData: WorkflowFileData): void {
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
			// Send message to VS Code extension via the VS Code API
			vscode.postMessage({
				type: 'workflowUpdate',
				workflow: {
					name: workflowData.name,
					nodes: workflowData.nodes,
					connections: workflowData.connections,
					settings: workflowData.settings,
					pinData: workflowData.pinData,
				},
			});
			console.log('[WorkflowFileSync] Sent workflow update to VS Code:', workflowData.name);
		} catch (error) {
			console.error('[WorkflowFileSync] Failed to send workflow update:', error);
		}
	}

	/**
	 * Sync workflow from IWorkflowDb type
	 */
	function syncFromWorkflowDb(workflow: IWorkflowDb): void {
		syncWorkflowToFile({
			name: workflow.name,
			nodes: workflow.nodes,
			connections: workflow.connections,
			settings: workflow.settings,
			pinData: workflow.pinData,
		});
	}

	return {
		isVSCodeWebview,
		syncWorkflowToFile,
		syncFromWorkflowDb,
	};
}
