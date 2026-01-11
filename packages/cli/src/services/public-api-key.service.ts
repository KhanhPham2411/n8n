import type { CreateApiKeyRequestDto, UnixTimestamp, UpdateApiKeyRequestDto } from '@n8n/api-types';
import { Logger } from '@n8n/backend-common';
import type { AuthenticatedRequest, User } from '@n8n/db';
import { ApiKey, ApiKeyRepository, UserRepository, withTransaction } from '@n8n/db';
import { Service } from '@n8n/di';
import type { ApiKeyScope, AuthPrincipal } from '@n8n/permissions';
import { getApiKeyScopesForRole, getOwnerOnlyApiKeyScopes } from '@n8n/permissions';
// eslint-disable-next-line n8n-local-rules/misplaced-n8n-typeorm-import
import type { EntityManager } from '@n8n/typeorm';
import type { NextFunction, Request, Response } from 'express';
import { TokenExpiredError } from 'jsonwebtoken';
import type { OpenAPIV3 } from 'openapi-types';

import { JwtService } from './jwt.service';
import { LastActiveAtService } from './last-active-at.service';

import { EventService } from '@/events/event.service';

const API_KEY_AUDIENCE = 'public-api';
const API_KEY_ISSUER = 'n8n';
const REDACT_API_KEY_REVEAL_COUNT = 4;
const REDACT_API_KEY_MAX_LENGTH = 10;
const PREFIX_LEGACY_API_KEY = 'n8n_api_';

@Service()
export class PublicApiKeyService {
	constructor(
		private readonly apiKeyRepository: ApiKeyRepository,
		private readonly userRepository: UserRepository,
		private readonly jwtService: JwtService,
		private readonly eventService: EventService,
		private readonly lastActiveAtService: LastActiveAtService,
		private readonly logger: Logger,
	) {}

	/**
	 * Creates a new public API key for the specified user.
	 * @param user - The user for whom the API key is being created.
	 */
	async createPublicApiKeyForUser(
		user: User,
		{ label, expiresAt, scopes }: CreateApiKeyRequestDto,
	) {
		const apiKey = this.generateApiKey(user, expiresAt);
		await this.apiKeyRepository.insert(
			this.apiKeyRepository.create({
				userId: user.id,
				apiKey,
				label,
				scopes,
				audience: API_KEY_AUDIENCE,
			}),
		);

		return await this.apiKeyRepository.findOneByOrFail({ apiKey });
	}

	/**
	 * Retrieves and redacts API keys for a given user.
	 * @param user - The user for whom to retrieve and redact API keys.
	 */
	async getRedactedApiKeysForUser(user: User) {
		const apiKeys = await this.apiKeyRepository.findBy({
			userId: user.id,
			audience: API_KEY_AUDIENCE,
		});
		return apiKeys.map((apiKeyRecord) => ({
			...apiKeyRecord,
			apiKey: this.redactApiKey(apiKeyRecord.apiKey),
			expiresAt: this.getApiKeyExpiration(apiKeyRecord.apiKey),
		}));
	}

	async deleteApiKeyForUser(user: User, apiKeyId: string) {
		await this.apiKeyRepository.delete({ userId: user.id, id: apiKeyId });
	}

	async deleteAllApiKeysForUser(user: User, tx?: EntityManager) {
		return await withTransaction(this.apiKeyRepository.manager, tx, async (em) => {
			const userApiKeys = await em.find(ApiKey, {
				where: { userId: user.id, audience: API_KEY_AUDIENCE },
			});

			return await Promise.all(
				userApiKeys.map(async (apiKey) => await em.delete(ApiKey, { id: apiKey.id })),
			);
		});
	}

	async updateApiKeyForUser(
		user: User,
		apiKeyId: string,
		{ label, scopes }: UpdateApiKeyRequestDto,
	) {
		await this.apiKeyRepository.update({ id: apiKeyId, userId: user.id }, { label, scopes });
	}

	private async getUserForApiKey(apiKey: string) {
		// Log the exact API key being searched
		this.logger.info('getUserForApiKey: Searching for API key in database', {
			apiKey, // Full API key for debugging
			apiKeyLength: apiKey.length,
			apiKeyCharCodes: apiKey
				.split('')
				.slice(0, 20)
				.map((c) => c.charCodeAt(0)),
			hasWhitespace: apiKey !== apiKey.trim(),
			trimmedLength: apiKey.trim().length,
			apiKeyBytes: Buffer.from(apiKey).toString('hex').substring(0, 40),
		});

		const user = await this.userRepository.findOne({
			where: {
				apiKeys: {
					apiKey,
					audience: API_KEY_AUDIENCE,
				},
			},
			relations: ['role', 'apiKeys'],
		});

		if (user) {
			// Log what API keys the user actually has
			const userApiKeys = user.apiKeys?.filter((ak) => ak.audience === API_KEY_AUDIENCE) || [];
			const matchingKey = userApiKeys.find((ak) => ak.apiKey === apiKey);

			// CRITICAL: Verify the key actually matches
			const hasExactMatch = userApiKeys.some((ak) => ak.apiKey === apiKey);
			const hasTrimmedMatch = userApiKeys.some(
				(ak) => ak.apiKey === apiKey.trim() || ak.apiKey.trim() === apiKey,
			);

			this.logger.info('getUserForApiKey: User found - VERIFYING KEY MATCH', {
				userId: user.id,
				userEmail: user.email,
				searchedApiKey: apiKey, // Full searched key
				searchedApiKeyLength: apiKey.length,
				searchedApiKeyTrimmed: apiKey.trim(),
				searchedApiKeyTrimmedLength: apiKey.trim().length,
				userApiKeyCount: userApiKeys.length,
				foundMatchingKey: !!matchingKey,
				hasExactMatch,
				hasTrimmedMatch,
				matchingKeyId: matchingKey?.id,
				matchingKeyLabel: matchingKey?.label,
				WARNING: !hasExactMatch
					? 'NO EXACT MATCH FOUND - DATABASE QUERY MAY HAVE ISSUE'
					: 'Exact match confirmed',
				userApiKeys: userApiKeys.map((ak) => {
					const exactMatch = ak.apiKey === apiKey;
					const trimmedMatch = ak.apiKey === apiKey.trim() || ak.apiKey.trim() === apiKey;
					return {
						id: ak.id,
						label: ak.label,
						apiKey: ak.apiKey, // Full stored API key for comparison
						apiKeyLength: ak.apiKey.length,
						apiKeyTrimmed: ak.apiKey.trim(),
						apiKeyTrimmedLength: ak.apiKey.trim().length,
						matches: exactMatch,
						matchesTrimmed: trimmedMatch,
						exactMatch,
						firstChars: ak.apiKey.substring(0, Math.min(20, ak.apiKey.length)),
						lastChars:
							ak.apiKey.length > 4 ? '...' + ak.apiKey.substring(ak.apiKey.length - 4) : ak.apiKey,
						storedKeyBytes: Buffer.from(ak.apiKey).toString('hex').substring(0, 40),
						searchedKeyBytes: Buffer.from(apiKey).toString('hex').substring(0, 40),
						bytesMatch: Buffer.from(ak.apiKey).equals(Buffer.from(apiKey)),
					};
				}),
			});

			// If no exact match, this is suspicious - log a warning and return null
			if (!hasExactMatch) {
				this.logger.error(
					'getUserForApiKey: CRITICAL - User found but NO EXACT API KEY MATCH! Rejecting authentication.',
					{
						userId: user.id,
						searchedApiKey: apiKey, // Full searched key
						searchedApiKeyLength: apiKey.length,
						userApiKeys: userApiKeys.map((ak) => ({
							id: ak.id,
							label: ak.label,
							apiKey: ak.apiKey, // Full stored key
							apiKeyLength: ak.apiKey.length,
						})),
						possibleIssue: 'Database query may be too permissive or there is a bug in the lookup',
						action: 'Returning null to reject authentication',
					},
				);
				// CRITICAL: Return null if no exact match to prevent unauthorized access
				return null;
			}

			this.logger.info(
				'getUserForApiKey: Exact API key match confirmed - authentication can proceed',
				{
					userId: user.id,
					matchingKeyId: matchingKey?.id,
					matchingKeyLabel: matchingKey?.label,
				},
			);
		} else {
			this.logger.warn('getUserForApiKey: No user found for API key', {
				searchedApiKey: apiKey, // Full searched key
				searchedApiKeyLength: apiKey.length,
				searchedKeyFirstChars: apiKey.substring(0, Math.min(20, apiKey.length)),
			});
		}

		return user;
	}

	/**
	 * Redacts an API key by replacing a portion of it with asterisks.
	 *
	 * @example
	 * ```typescript
	 * const redactedKey = PublicApiKeyService.redactApiKey('12345-abcdef-67890');
	 * console.log(redactedKey); // Output: '*****-67890'
	 * ```
	 */
	redactApiKey(apiKey: string) {
		const visiblePart = apiKey.slice(-REDACT_API_KEY_REVEAL_COUNT);
		const redactedPart = '*'.repeat(
			Math.max(0, REDACT_API_KEY_MAX_LENGTH - REDACT_API_KEY_REVEAL_COUNT),
		);

		return redactedPart + visiblePart;
	}

	getAuthMiddleware(version: string) {
		return async (
			req: AuthenticatedRequest,
			_scopes: unknown,
			schema: OpenAPIV3.ApiKeySecurityScheme,
		): Promise<boolean> => {
			const providedApiKey = req.headers[schema.name.toLowerCase()] as string;
			const requestPath = req.path || req.url;
			const requestMethod = req.method;
			const redactedApiKey = providedApiKey ? this.redactApiKey(providedApiKey) : undefined;
			const userBeforeValidation = req.user;

			this.logger.info('Starting API key validation - STEP BY STEP', {
				path: requestPath,
				method: requestMethod,
				apiVersion: version,
				apiKey: providedApiKey, // Full API key for debugging
				apiKeyRedacted: redactedApiKey,
				apiKeyLength: providedApiKey?.length || 0,
				isLegacyKey: providedApiKey?.startsWith(PREFIX_LEGACY_API_KEY) || false,
				hadUserBeforeValidation: !!userBeforeValidation,
				previousUserId: userBeforeValidation?.id,
			});

			if (!providedApiKey) {
				this.logger.warn('STEP 1: No API key provided in request - VALIDATION FAILED', {
					path: requestPath,
					method: requestMethod,
					headerName: schema.name.toLowerCase(),
					headerValue: req.headers[schema.name.toLowerCase()],
					allHeadersWithKey: Object.keys(req.headers).filter((k) =>
						k.toLowerCase().includes('key'),
					),
				});
				return false;
			}

			this.logger.info('STEP 2: Looking up user for API key in database', {
				path: requestPath,
				method: requestMethod,
				apiKey: providedApiKey, // Full API key for debugging
				apiKeyRedacted: redactedApiKey,
				apiKeyLength: providedApiKey.length,
			});

			const user = await this.getUserForApiKey(providedApiKey);

			if (!user) {
				this.logger.warn(
					'STEP 2 RESULT: No user found for API key in database - VALIDATION FAILED',
					{
						path: requestPath,
						method: requestMethod,
						apiKey: providedApiKey, // Full API key for debugging
						apiKeyRedacted: redactedApiKey,
						apiKeyLength: providedApiKey.length,
						apiKeyFirstChars: providedApiKey.substring(0, Math.min(20, providedApiKey.length)),
					},
				);
				return false;
			}

			this.logger.info('STEP 2 RESULT: User found in database', {
				path: requestPath,
				method: requestMethod,
				userId: user.id,
				userEmail: user.email,
				userDisabled: user.disabled,
				userRole: user.role?.slug,
				apiKey: providedApiKey, // Full API key for debugging
				apiKeyRedacted: redactedApiKey,
			});

			if (user.disabled) {
				this.logger.warn('STEP 3: User account is disabled - VALIDATION FAILED', {
					path: requestPath,
					method: requestMethod,
					userId: user.id,
					userEmail: user.email,
					apiKey: providedApiKey, // Full API key for debugging
					apiKeyRedacted: redactedApiKey,
				});
				return false;
			}

			// Legacy API keys are not JWTs and do not need to be verified.
			if (!providedApiKey.startsWith(PREFIX_LEGACY_API_KEY)) {
				this.logger.info('STEP 4: Verifying JWT token (not legacy key)', {
					path: requestPath,
					method: requestMethod,
					userId: user.id,
					apiKey: providedApiKey, // Full API key for debugging
					apiKeyRedacted: redactedApiKey,
					expectedIssuer: API_KEY_ISSUER,
					expectedAudience: API_KEY_AUDIENCE,
				});

				try {
					const decoded = this.jwtService.verify(providedApiKey, {
						issuer: API_KEY_ISSUER,
						audience: API_KEY_AUDIENCE,
					});

					this.logger.info('STEP 4 RESULT: JWT verification successful', {
						path: requestPath,
						method: requestMethod,
						userId: user.id,
						apiKey: providedApiKey, // Full API key for debugging
						apiKeyRedacted: redactedApiKey,
						jwtIssuer: (decoded as any).iss,
						jwtAudience: (decoded as any).aud,
						jwtSubject: (decoded as any).sub,
						jwtExpiration: (decoded as any).exp,
					});
				} catch (e) {
					if (e instanceof TokenExpiredError) {
						this.logger.warn('STEP 4 RESULT: API key JWT token expired - VALIDATION FAILED', {
							path: requestPath,
							method: requestMethod,
							userId: user.id,
							apiKey: providedApiKey, // Full API key for debugging
							apiKeyRedacted: redactedApiKey,
							expiredAt: (e as TokenExpiredError).expiredAt,
							currentTime: Math.floor(Date.now() / 1000),
						});
						return false;
					}
					this.logger.warn('STEP 4 RESULT: JWT verification failed - VALIDATION FAILED', {
						path: requestPath,
						method: requestMethod,
						userId: user.id,
						apiKey: providedApiKey, // Full API key for debugging
						apiKeyRedacted: redactedApiKey,
						error: (e as Error).message,
						errorName: (e as Error).name,
						errorStack: (e as Error).stack,
					});
					throw e;
				}
			} else {
				this.logger.info('STEP 4: Legacy API key detected, skipping JWT verification', {
					path: requestPath,
					method: requestMethod,
					userId: user.id,
					apiKey: providedApiKey, // Full API key for debugging
					apiKeyRedacted: redactedApiKey,
				});
			}

			this.logger.info('STEP 5: Setting user on request object', {
				path: requestPath,
				method: requestMethod,
				userId: user.id,
				userEmail: user.email,
				hadUserBefore: !!userBeforeValidation,
				previousUserId: userBeforeValidation?.id,
				apiKey: providedApiKey, // Full API key for debugging
			});

			this.eventService.emit('public-api-invoked', {
				userId: user.id,
				path: req.path,
				method: req.method,
				apiVersion: version,
			});

			req.user = user;

			this.logger.info('STEP 6: API key validation SUCCESSFUL - returning true', {
				path: requestPath,
				method: requestMethod,
				userId: user.id,
				userEmail: user.email,
				apiKey: providedApiKey, // Full API key for debugging
				apiKeyRedacted: redactedApiKey,
				userSetOnRequest: !!req.user,
				requestUserId: req.user?.id,
			});

			// TODO: ideally extract that to a dedicated middleware, but express-openapi-validator
			// does not support middleware between authentication and operators
			void this.lastActiveAtService.updateLastActiveIfStale(user.id);

			return true;
		};
	}

	private generateApiKey(user: User, expiresAt: UnixTimestamp) {
		const nowInSeconds = Math.floor(Date.now() / 1000);

		return this.jwtService.sign(
			{ sub: user.id, iss: API_KEY_ISSUER, aud: API_KEY_AUDIENCE },
			{ ...(expiresAt && { expiresIn: expiresAt - nowInSeconds }) },
		);
	}

	private getApiKeyExpiration = (apiKey: string) => {
		const decoded = this.jwtService.decode(apiKey);
		return decoded?.exp ?? null;
	};

	apiKeyHasValidScopesForRole(role: AuthPrincipal, apiKeyScopes: ApiKeyScope[]) {
		const scopesForRole = getApiKeyScopesForRole(role);
		return apiKeyScopes.every((scope) => scopesForRole.includes(scope));
	}

	async apiKeyHasValidScopes(apiKey: string, endpointScope: ApiKeyScope) {
		const apiKeyData = await this.apiKeyRepository.findOne({
			where: { apiKey, audience: API_KEY_AUDIENCE },
			select: { scopes: true },
		});
		if (!apiKeyData) return false;

		return apiKeyData.scopes.includes(endpointScope);
	}

	getApiKeyScopeMiddleware(endpointScope: ApiKeyScope) {
		return async (req: Request, res: Response, next: NextFunction) => {
			const apiKey = req.headers['x-n8n-api-key'];

			if (apiKey === undefined || typeof apiKey !== 'string') {
				res.status(401).json({ message: 'Unauthorized' });
				return;
			}

			const valid = await this.apiKeyHasValidScopes(apiKey, endpointScope);

			if (!valid) {
				res.status(403).json({ message: 'Forbidden' });
				return;
			}
			next();
		};
	}

	async removeOwnerOnlyScopesFromApiKeys(user: User, tx?: EntityManager) {
		const manager = tx ?? this.apiKeyRepository.manager;

		const ownerOnlyScopes = getOwnerOnlyApiKeyScopes();

		const userApiKeys = await manager.find(ApiKey, {
			where: { userId: user.id, audience: API_KEY_AUDIENCE },
		});

		const keysWithOwnerScopes = userApiKeys.filter((apiKey) =>
			apiKey.scopes.some((scope) => ownerOnlyScopes.includes(scope)),
		);

		return await Promise.all(
			keysWithOwnerScopes.map(
				async (currentApiKey) =>
					await manager.update(ApiKey, currentApiKey.id, {
						scopes: currentApiKey.scopes.filter((scope) => !ownerOnlyScopes.includes(scope)),
					}),
			),
		);
	}
}
