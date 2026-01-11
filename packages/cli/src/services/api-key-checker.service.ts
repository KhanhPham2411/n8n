import { ApiKeyRepository } from '@n8n/db';
import { Service } from '@n8n/di';

const API_KEY_AUDIENCE = 'public-api';
const ATOM_API_KEY_LABEL = 'n8n Atom Key';

@Service()
export class ApiKeyCheckerService {
	constructor(private readonly apiKeyRepository: ApiKeyRepository) {}

	/**
	 * Checks if any n8n Atom API keys are configured in the system.
	 * Only n8n Atom keys (with label 'n8n Atom Key') are checked, not regular API keys.
	 * Used to determine if API key authentication should be enforced for webview access.
	 * @returns Promise<boolean> - True if at least one n8n Atom API key exists, false otherwise
	 */
	async hasApiKeysConfigured(): Promise<boolean> {
		const count = await this.apiKeyRepository.count({
			where: { audience: API_KEY_AUDIENCE, label: ATOM_API_KEY_LABEL },
		});
		return count > 0;
	}
}
