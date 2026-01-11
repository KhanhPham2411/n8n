import { useWorkflowsStore } from '@/app/stores/workflows.store';
import { VIEWS } from '@/app/constants';
import type { IWorkflowDb } from '@/Interface';
import type { INodeUi, IConnections } from 'n8n-workflow';

export interface WorkflowSyncData {
	name: string;
	nodes: INodeUi[];
	connections: IConnections;
	settings?: Record<string, unknown>;
	pinData?: Record<string, unknown>;
}

export interface WorkflowSyncResult {
	workflow: IWorkflowDb;
	action: 'created' | 'updated' | 'unchanged';
}

export function useWorkflowSync() {
	const workflowsStore = useWorkflowsStore();
	// Note: Can't use useRouter() here as this composable may be called outside setup context.
	// Instead, we use the globally exposed router via window.__n8n_router__

	/**
	 * Find a workflow by exact name match in the backend
	 */
	async function findWorkflowByName(name: string): Promise<IWorkflowDb | null> {
		try {
			const workflows = await workflowsStore.searchWorkflows({ query: name });
			// Find exact match (case-sensitive)
			return workflows.find((w) => w.name === name) || null;
		} catch (error) {
			console.error('[WorkflowSync] Failed to search workflows:', error);
			return null;
		}
	}

	/**
	 * Compare two workflows to check if they have meaningful differences
	 * Returns true if there are changes that need to be synced
	 */
	function hasWorkflowChanges(existing: IWorkflowDb, incoming: WorkflowSyncData): boolean {
		try {
			// Handle cases where nodes might not be loaded
			const existingNodesList = existing.nodes || [];
			const incomingNodesList = incoming.nodes || [];

			// If node counts differ, there are definitely changes
			if (existingNodesList.length !== incomingNodesList.length) {
				return true;
			}

			// Compare nodes - stringify and compare
			const existingNodes = JSON.stringify(
				existingNodesList.map((n) => ({
					name: n.name,
					type: n.type,
					typeVersion: n.typeVersion,
					position: n.position,
					parameters: n.parameters,
					credentials: n.credentials,
					disabled: n.disabled,
				})),
			);
			const incomingNodes = JSON.stringify(
				incomingNodesList.map((n) => ({
					name: n.name,
					type: n.type,
					typeVersion: n.typeVersion,
					position: n.position,
					parameters: n.parameters,
					credentials: n.credentials,
					disabled: n.disabled,
				})),
			);

			if (existingNodes !== incomingNodes) {
				console.log('[WorkflowSync] Nodes have changed');
				return true;
			}

			// Compare connections
			const existingConnections = JSON.stringify(existing.connections || {});
			const incomingConnections = JSON.stringify(incoming.connections || {});

			if (existingConnections !== incomingConnections) {
				console.log('[WorkflowSync] Connections have changed');
				return true;
			}

			console.log('[WorkflowSync] No changes detected');
			return false;
		} catch (error) {
			console.error('[WorkflowSync] Error comparing workflows:', error);
			// If we can't compare, assume there are changes
			return true;
		}
	}

	/**
	 * Sync workflow from file to n8n backend
	 * - If workflow exists and has changes: update it
	 * - If workflow exists with no changes: just return it
	 * - If workflow doesn't exist: create it
	 */
	async function syncWorkflow(workflowData: WorkflowSyncData): Promise<WorkflowSyncResult> {
		const existingWorkflow = await findWorkflowByName(workflowData.name);

		if (existingWorkflow) {
			// Workflow exists - check for changes
			if (hasWorkflowChanges(existingWorkflow, workflowData)) {
				// Update existing workflow
				const updated = await workflowsStore.updateWorkflow(existingWorkflow.id, {
					nodes: workflowData.nodes,
					connections: workflowData.connections,
					settings: workflowData.settings,
					pinData: workflowData.pinData,
				});

				return { workflow: updated, action: 'updated' };
			} else {
				console.log('[WorkflowSync] No changes detected, using existing workflow');
				return { workflow: existingWorkflow, action: 'unchanged' };
			}
		} else {
			console.log('[WorkflowSync] Creating new workflow...');

			// Create new workflow
			const newWorkflow = await workflowsStore.createNewWorkflow({
				name: workflowData.name,
				nodes: workflowData.nodes,
				connections: workflowData.connections,
				settings: workflowData.settings || {},
			});

			console.log('[WorkflowSync] New workflow created with ID:', newWorkflow.id);
			return { workflow: newWorkflow, action: 'created' };
		}
	}

	/**
	 * Navigate to workflow view using globally exposed router
	 */
	async function navigateToWorkflow(workflowId: string): Promise<void> {
		// Use globally exposed router since useRouter() doesn't work outside setup context
		const globalRouter = (
			window as unknown as { __n8n_router__?: { push: (route: unknown) => Promise<void> } }
		).__n8n_router__;
		if (globalRouter) {
			await globalRouter.push({
				name: VIEWS.WORKFLOW,
				params: { name: workflowId },
			});
		} else {
			// Fallback to location change if router not available
			console.warn('[WorkflowSync] Global router not available, using location change');
			window.location.hash = `#/workflow/${workflowId}`;
		}
	}

	/**
	 * Full sync and navigate flow
	 * Syncs the workflow and navigates to it
	 */
	async function syncAndNavigate(workflowData: WorkflowSyncData): Promise<WorkflowSyncResult> {
		const result = await syncWorkflow(workflowData);
		await navigateToWorkflow(result.workflow.id);
		return result;
	}

	return {
		findWorkflowByName,
		hasWorkflowChanges,
		syncWorkflow,
		navigateToWorkflow,
		syncAndNavigate,
	};
}
