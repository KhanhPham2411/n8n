import { CreateApiKeyRequestDto, UpdateApiKeyRequestDto } from '@n8n/api-types';
import { AuthenticatedRequest, GLOBAL_OWNER_ROLE, UserRepository } from '@n8n/db';
import {
	Body,
	Delete,
	Get,
	GlobalScope,
	Param,
	Patch,
	Post,
	RestController,
} from '@n8n/decorators';
import { getApiKeyScopesForRole, OWNER_API_KEY_SCOPES } from '@n8n/permissions';
import type { RequestHandler } from 'express';

import { BadRequestError } from '@/errors/response-errors/bad-request.error';
import { EventService } from '@/events/event.service';
import { isApiEnabled } from '@/public-api';
import { PublicApiKeyService } from '@/services/public-api-key.service';

export const isApiEnabledMiddleware: RequestHandler = (_, res, next) => {
	if (isApiEnabled()) {
		next();
	} else {
		res.status(404).end();
	}
};

@RestController('/api-keys')
export class ApiKeysController {
	constructor(
		private readonly eventService: EventService,
		private readonly publicApiKeyService: PublicApiKeyService,
		private readonly userRepository: UserRepository,
	) {}

	/**
	 * Create an API Key
	 */
	@GlobalScope('apiKey:manage')
	@Post('/', { middlewares: [isApiEnabledMiddleware] })
	async createApiKey(
		req: AuthenticatedRequest,
		_res: Response,
		@Body body: CreateApiKeyRequestDto,
	) {
		if (!this.publicApiKeyService.apiKeyHasValidScopesForRole(req.user, body.scopes)) {
			throw new BadRequestError('Invalid scopes for user role');
		}

		const newApiKey = await this.publicApiKeyService.createPublicApiKeyForUser(req.user, body);

		this.eventService.emit('public-api-key-created', { user: req.user, publicApi: false });

		return {
			...newApiKey,
			apiKey: this.publicApiKeyService.redactApiKey(newApiKey.apiKey),
			rawApiKey: newApiKey.apiKey,
			expiresAt: body.expiresAt,
		};
	}

	/**
	 * Get API keys
	 */
	@GlobalScope('apiKey:manage')
	@Get('/', { middlewares: [isApiEnabledMiddleware] })
	async getApiKeys(req: AuthenticatedRequest) {
		const apiKeys = await this.publicApiKeyService.getRedactedApiKeysForUser(req.user);
		return apiKeys;
	}

	/**
	 * Delete an API Key
	 */
	@GlobalScope('apiKey:manage')
	@Delete('/:id', { middlewares: [isApiEnabledMiddleware] })
	async deleteApiKey(req: AuthenticatedRequest, _res: Response, @Param('id') apiKeyId: string) {
		await this.publicApiKeyService.deleteApiKeyForUser(req.user, apiKeyId);

		this.eventService.emit('public-api-key-deleted', { user: req.user, publicApi: false });

		return { success: true };
	}

	/**
	 * Patch an API Key
	 */
	@GlobalScope('apiKey:manage')
	@Patch('/:id', { middlewares: [isApiEnabledMiddleware] })
	async updateApiKey(
		req: AuthenticatedRequest,
		_res: Response,
		@Param('id') apiKeyId: string,
		@Body body: UpdateApiKeyRequestDto,
	) {
		if (!this.publicApiKeyService.apiKeyHasValidScopesForRole(req.user, body.scopes)) {
			throw new BadRequestError('Invalid scopes for user role');
		}

		await this.publicApiKeyService.updateApiKeyForUser(req.user, apiKeyId, body);

		return { success: true };
	}

	@GlobalScope('apiKey:manage')
	@Get('/scopes', { middlewares: [isApiEnabledMiddleware] })
	async getApiKeyScopes(req: AuthenticatedRequest, _res: Response) {
		const scopes = getApiKeyScopesForRole(req.user);
		return scopes;
	}

	/**
	 * Create an n8n Atom API Key (for VS Code extension)
	 * Creates an API key for the owner user with all owner scopes, no expiration
	 */
	@GlobalScope('apiKey:manage')
	@Post('/atom', { middlewares: [isApiEnabledMiddleware] })
	async createAtomApiKey(req: AuthenticatedRequest, _res: Response) {
		// Get the owner user
		const owner = await this.userRepository.findOne({
			where: { role: { slug: GLOBAL_OWNER_ROLE.slug } },
			relations: ['role'],
		});

		if (!owner) {
			throw new BadRequestError('Owner user not found');
		}

		// Create API key with all owner scopes, no expiration, labeled for Atom
		const newApiKey = await this.publicApiKeyService.createPublicApiKeyForUser(owner, {
			label: 'n8n Atom Key',
			expiresAt: null,
			scopes: OWNER_API_KEY_SCOPES,
		});

		this.eventService.emit('public-api-key-created', { user: owner, publicApi: false });

		return {
			...newApiKey,
			apiKey: this.publicApiKeyService.redactApiKey(newApiKey.apiKey),
			rawApiKey: newApiKey.apiKey,
			expiresAt: null,
		};
	}
}
