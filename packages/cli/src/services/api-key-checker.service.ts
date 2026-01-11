import { ApiKeyRepository } from '@n8n/db';
import { Service } from '@n8n/di';

const API_KEY_AUDIENCE = 'public-api';

@Service()
export class ApiKeyCheckerService {
	constructor(private readonly apiKeyRepository: ApiKeyRepository) {}

	/**
	 * Checks if any API keys are configured in the system.
	 * Used to determine if API key authentication should be enforced for webview access.
	 * @returns Promise<boolean> - True if at least one API key exists, false otherwise
	 */
	async hasApiKeysConfigured(): Promise<boolean> {
		const count = await this.apiKeyRepository.count({
			where: { audience: API_KEY_AUDIENCE },
		});
		return count > 0;
	}
}
