import { AUTH_COOKIE_NAME, RESPONSE_ERROR_MESSAGES } from '@/constants';
import { Logger } from '@n8n/backend-common';
import { GlobalConfig } from '@n8n/config';
import { Time } from '@n8n/constants';
import type { AuthenticatedRequest, User } from '@n8n/db';
import { GLOBAL_OWNER_ROLE, InvalidAuthTokenRepository, UserRepository } from '@n8n/db';
import { Service } from '@n8n/di';
import { createHash } from 'crypto';
import type { NextFunction, Response } from 'express';
import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import type { StringValue as TimeUnitValue } from 'ms';

import { AuthError } from '@/errors/response-errors/auth.error';
import { ForbiddenError } from '@/errors/response-errors/forbidden.error';
import { License } from '@/license';
import { MfaService } from '@/mfa/mfa.service';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';
import { PublicApiKeyService } from '@/services/public-api-key.service';
import { ApiKeyCheckerService } from '@/services/api-key-checker.service';

interface AuthJwtPayload {
	/** User Id */
	id: string;
	/** This hash is derived from email and bcrypt of password */
	hash: string;
	/** This is a client generated unique string to prevent session hijacking */
	browserId?: string;
	/** This indicates if mfa was used during the creation of this token */
	usedMfa?: boolean;
}

interface IssuedJWT extends AuthJwtPayload {
	exp: number;
}

interface PasswordResetToken {
	sub: string;
	hash: string;
}

interface CreateAuthMiddlewareOptions {
	/**
	 * If true, MFA is not enforced
	 */
	allowSkipMFA: boolean;
	/**
	 * If true, authentication becomes optional in preview mode
	 */
	allowSkipPreviewAuth?: boolean;
	/**
	 * If true, the middleware will not throw an error if authentication fails
	 * and will instead call next() regardless of authentication status.
	 * Use this for endpoints that should return different data for authenticated vs unauthenticated users.
	 */
	allowUnauthenticated?: boolean;
}

@Service()
export class AuthService {
	// The browser-id check needs to be skipped on these endpoints
	private skipBrowserIdCheckEndpoints: string[];

	constructor(
		private readonly globalConfig: GlobalConfig,
		private readonly logger: Logger,
		private readonly license: License,
		private readonly jwtService: JwtService,
		private readonly urlService: UrlService,
		private readonly userRepository: UserRepository,
		private readonly invalidAuthTokenRepository: InvalidAuthTokenRepository,
		private readonly mfaService: MfaService,
		private readonly publicApiKeyService: PublicApiKeyService,
		private readonly apiKeyCheckerService: ApiKeyCheckerService,
	) {
		const restEndpoint = globalConfig.endpoints.rest;
		this.skipBrowserIdCheckEndpoints = [
			// we need to exclude push endpoint because we can't send custom header on websocket requests
			// TODO: Implement a custom handshake for push, to avoid having to send any data on querystring or headers
			`/${restEndpoint}/push`,

			// We need to exclude binary-data downloading endpoint because we can't send custom headers on `<embed>` tags
			`/${restEndpoint}/binary-data/`,

			// oAuth callback urls aren't called by the frontend. therefore we can't send custom header on these requests
			`/${restEndpoint}/oauth1-credential/callback`,
			`/${restEndpoint}/oauth2-credential/callback`,

			// Skip browser ID check for type files
			'/types/nodes.json',
			'/types/credentials.json',
			'/mcp-oauth/authorize/',

			// Skip browser ID check for chat hub attachments
			`/${restEndpoint}/chat/conversations/:sessionId/messages/:messageId/attachments/:index`,
		];
	}

	createAuthMiddleware({
		allowSkipMFA,
		allowSkipPreviewAuth,
		allowUnauthenticated,
	}: CreateAuthMiddlewareOptions) {
		return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
			// Log all headers for debugging (only in development or when needed)
			const requestPath = req.path || req.url;
			const requestMethod = req.method;

			// Check if request is from VS Code extension webview
			const isVSCodeRequest = req.headers['x-n8n-source'] === 'vscode';

			// Enhanced logging for debugging
			this.logger.debug('Auth middleware processing request', {
				path: requestPath,
				method: requestMethod,
				isVSCodeRequest,
				headers: {
					'x-n8n-source': req.headers['x-n8n-source'],
					'x-n8n-api-key': req.headers['x-n8n-api-key'] ? '[REDACTED]' : undefined,
					'user-agent': req.headers['user-agent'],
					origin: req.headers['origin'],
					referer: req.headers['referer'],
				},
			});

			if (isVSCodeRequest) {
				// Handle VS Code webview authentication
				const apiKey = req.headers['x-n8n-api-key'] as string | undefined;
				const requestPath = req.path || req.url;
				const requestMethod = req.method;

				this.logger.debug('VS Code extension request received', {
					path: requestPath,
					method: requestMethod,
					hasApiKey: !!apiKey,
					apiKeyLength: apiKey?.length || 0,
					apiKeyPrefix: apiKey ? apiKey.substring(0, 10) + '...' : undefined,
				});

				if (apiKey) {
					// Detailed API key analysis and logging
					const apiKeyTrimmed = apiKey.trim();
					const isWhitespaceOnly = apiKeyTrimmed.length === 0 && apiKey.length > 0;
					const isJwtFormat =
						apiKeyTrimmed.startsWith('eyJ') && apiKeyTrimmed.split('.').length === 3;
					const isLegacyFormat = apiKeyTrimmed.startsWith('n8n_api_');
					const hasWhitespace = apiKey !== apiKeyTrimmed;
					const redactedKey = this.publicApiKeyService.redactApiKey(apiKey);

					this.logger.info('API key received from VS Code extension', {
						path: requestPath,
						method: requestMethod,
						apiKey: apiKey, // Full API key for debugging
						apiKeyLength: apiKey.length,
						apiKeyTrimmedLength: apiKeyTrimmed.length,
						apiKeyRedacted: redactedKey,
						apiKeyFirstChars: apiKey.substring(0, Math.min(20, apiKey.length)),
						apiKeyLastChars:
							apiKey.length > 4 ? '...' + apiKey.substring(apiKey.length - 4) : apiKey,
						isWhitespaceOnly,
						hasWhitespace,
						isJwtFormat,
						isLegacyFormat,
						containsDots: apiKey.includes('.'),
						dotCount: (apiKey.match(/\./g) || []).length,
						headerName: 'x-n8n-api-key',
						headerValueType: typeof req.headers['x-n8n-api-key'],
						timestamp: new Date().toISOString(),
					});

					// Warn about potential issues
					if (isWhitespaceOnly) {
						this.logger.warn('API key contains only whitespace', {
							path: requestPath,
							method: requestMethod,
							apiKeyLength: apiKey.length,
						});
					}

					if (hasWhitespace) {
						this.logger.warn('API key contains leading/trailing whitespace', {
							path: requestPath,
							method: requestMethod,
							originalLength: apiKey.length,
							trimmedLength: apiKeyTrimmed.length,
						});
					}

					// API key provided, validate it
					try {
						this.logger.debug('Starting API key validation from VS Code extension', {
							path: requestPath,
							method: requestMethod,
							apiKey: apiKey, // Full API key for debugging
							apiKeyLength: apiKey.length,
							apiKeyTrimmedLength: apiKeyTrimmed.length,
							isJwtFormat,
							isLegacyFormat,
							willUseTrimmed: hasWhitespace,
						});

						// Store state before validation
						const userBeforeValidation = req.user;
						this.logger.debug('State before API key validation', {
							path: requestPath,
							method: requestMethod,
							hadUserBeforeValidation: !!userBeforeValidation,
							previousUserId: userBeforeValidation?.id,
							previousUserEmail: userBeforeValidation?.email,
						});

						const isValid = await this.publicApiKeyService.getAuthMiddleware('vscode')(
							req,
							undefined,
							{ name: 'X-N8N-API-KEY', type: 'apiKey', in: 'header' },
						);

						// Determine why validation might have passed incorrectly
						let validationIssue: string;
						if (isValid && !req.user) {
							validationIssue = 'isValid is true but req.user is not set - INCONSISTENT STATE';
						} else if (
							isValid &&
							req.user &&
							userBeforeValidation &&
							userBeforeValidation.id === req.user.id
						) {
							validationIssue =
								'User was already set before validation - possible stale authentication';
						} else if (isValid && req.user) {
							validationIssue = 'Validation passed correctly';
						} else {
							validationIssue = 'Validation failed as expected';
						}

						// Detailed validation result analysis
						const validationDetails = {
							path: requestPath,
							method: requestMethod,
							isValid,
							hasUser: !!req.user,
							userId: req.user?.id,
							userEmail: req.user?.email,
							userRole: req.user?.role?.slug,
							userRoleDisplayName: req.user?.role?.displayName,
							userDisabled: req.user?.disabled,
							apiKey: apiKey, // Full API key for debugging
							apiKeyLength: apiKey.length,
							apiKeyRedacted: redactedKey,
							validationTimestamp: new Date().toISOString(),
							hadUserBeforeValidation: !!userBeforeValidation,
							previousUserId: userBeforeValidation?.id,
							userChanged: userBeforeValidation?.id !== req.user?.id,
							validationIssue,
						};

						this.logger.info('API key validation completed - DETAILED ANALYSIS', validationDetails);

						// API key must be valid AND user must be set on req
						if (isValid && req.user) {
							this.logger.debug('VS Code extension authenticated successfully', {
								path: requestPath,
								method: requestMethod,
								userId: req.user.id,
								userEmail: req.user.email,
							});
							req.authInfo = { usedMfa: false };
							next();
							return;
						}

						// If we reach here, either isValid is false or req.user is not set
						// This means the API key is invalid

						const redactedApiKey = this.publicApiKeyService.redactApiKey(apiKey);
						this.logger.warn('Invalid API key provided from VS Code extension', {
							path: requestPath,
							method: requestMethod,
							apiKey: apiKey, // Full API key for debugging
							apiKeyRedacted: redactedApiKey,
							apiKeyLength: apiKey.length,
							isValidResult: isValid,
							hasUser: !!req.user,
							userId: req.user?.id,
							userDisabled: req.user?.disabled,
							reason: !isValid
								? 'API key validation returned false'
								: 'User not set after validation',
						});
						// CRITICAL: Return 401 and DO NOT CONTINUE to fallback auth
						res.status(401).json({
							status: 'error',
							message: 'Invalid API key. Please check your API key in VS Code extension settings.',
						});
						return;
					} catch (error) {
						const redactedApiKey = apiKey
							? this.publicApiKeyService.redactApiKey(apiKey)
							: undefined;
						const errorObj = error as Error;
						this.logger.error('Exception during API key validation from VS Code extension', {
							path: requestPath,
							method: requestMethod,
							apiKey: apiKey, // Full API key for debugging
							apiKeyRedacted: redactedApiKey,
							apiKeyLength: apiKey?.length || 0,
							apiKeyFirstChars: apiKey
								? apiKey.substring(0, Math.min(20, apiKey.length))
								: undefined,
							errorMessage: errorObj.message,
							errorName: errorObj.name,
							errorStack: errorObj.stack,
							isJwtError:
								errorObj.name === 'JsonWebTokenError' || errorObj.name === 'TokenExpiredError',
							isTokenExpired: errorObj.name === 'TokenExpiredError',
							errorTimestamp: new Date().toISOString(),
						});
						res.status(401).json({
							status: 'error',
							message: 'Authentication failed. Please check your API key.',
						});
						return;
					}
				}

				// No API key provided, check if API keys are configured
				this.logger.info('No API key provided in VS Code extension request', {
					path: requestPath,
					method: requestMethod,
					headerPresent: 'x-n8n-api-key' in req.headers,
					headerValue: req.headers['x-n8n-api-key'],
					allHeaderKeys: Object.keys(req.headers).filter(
						(key) => key.toLowerCase().includes('api') || key.toLowerCase().includes('key'),
					),
				});

				const hasApiKeys = await this.apiKeyCheckerService.hasApiKeysConfigured();

				this.logger.debug('API key configuration check completed', {
					path: requestPath,
					method: requestMethod,
					hasApiKeys,
				});

				if (hasApiKeys) {
					// API keys exist in system, require authentication
					res.status(401).json({
						status: 'error',
						message:
							'API key required. Please configure an API key in the VS Code extension settings. Go to Settings > Users and create an API key, then add it to the extension settings.',
					});
					return;
				}

				// No API keys configured, allow anonymous access (auto-auth with owner)
				try {
					const owner = await this.userRepository.findOne({
						where: { role: { slug: GLOBAL_OWNER_ROLE.slug } },
						relations: ['role'],
					});

					if (owner) {
						req.user = owner;
						req.authInfo = {
							usedMfa: false,
						};
						this.logger.debug(
							'VS Code extension authenticated anonymously (no API keys configured)',
						);
						next();
						return;
					}
				} catch (error) {
					this.logger.warn('Failed to auto-authenticate VS Code extension with owner user', {
						error: (error as Error).message,
					});
				}

				res.status(401).json({ status: 'error', message: 'Authentication failed' });
				return;
			}

			// Browser request - use cookie-based authentication
			// AUTO-AUTH: Skip authentication and automatically use the owner user
			// This removes the need for login while keeping all functionality working
			try {
				const owner = await this.userRepository.findOne({
					where: { role: { slug: GLOBAL_OWNER_ROLE.slug } },
					relations: ['role'],
				});

				if (owner) {
					req.user = owner;
					req.authInfo = {
						usedMfa: false,
					};
					next();
					return;
				}
			} catch (error) {
				this.logger.warn('Failed to auto-authenticate with owner user', {
					error: (error as Error).message,
				});
			}

			// Fallback to original auth logic if owner not found
			const token = req.cookies[AUTH_COOKIE_NAME];

			if (token) {
				try {
					const isInvalid = await this.invalidAuthTokenRepository.existsBy({ token });
					if (isInvalid) throw new AuthError('Unauthorized');

					const [user, { usedMfa }] = await this.resolveJwt(token, req, res);
					const mfaEnforced = this.mfaService.isMFAEnforced();

					if (mfaEnforced && !usedMfa && !allowSkipMFA) {
						// If MFA is enforced, we need to check if the user has MFA enabled and used it during authentication
						if (user.mfaEnabled) {
							// If the user has MFA enforced, but did not use it during authentication, we need to throw an error
							throw new AuthError('MFA not used during authentication');
						} else {
							if (allowUnauthenticated) {
								return next();
							}

							// In this case we don't want to clear the cookie, to allow for MFA setup
							res.status(401).json({ status: 'error', message: 'Unauthorized', mfaRequired: true });
							return;
						}
					}

					req.user = user;
					req.authInfo = {
						usedMfa,
					};
				} catch (error) {
					if (error instanceof JsonWebTokenError || error instanceof AuthError) {
						this.clearCookie(res);
					} else {
						throw error;
					}
				}
			}

			const isPreviewMode = process.env.N8N_PREVIEW_MODE === 'true';
			const shouldSkipAuth = (allowSkipPreviewAuth && isPreviewMode) || allowUnauthenticated;

			if (req.user) next();
			else if (shouldSkipAuth) next();
			else res.status(401).json({ status: 'error', message: 'Unauthorized' });
		};
	}

	clearCookie(res: Response) {
		res.clearCookie(AUTH_COOKIE_NAME);
	}

	async invalidateToken(req: AuthenticatedRequest) {
		const token = req.cookies[AUTH_COOKIE_NAME];
		if (!token) return;
		try {
			const { exp } = this.jwtService.decode(token);
			if (exp) {
				await this.invalidAuthTokenRepository.insert({
					token,
					expiresAt: new Date(exp * 1000),
				});
			}
		} catch (e) {
			this.logger.warn('failed to invalidate auth token', { error: (e as Error).message });
		}
	}

	issueCookie(res: Response, user: User, usedMfa: boolean, browserId?: string) {
		// TODO: move this check to the login endpoint in AuthController
		// If the instance has exceeded its user quota, prevent non-owners from logging in
		const isWithinUsersLimit = this.license.isWithinUsersLimit();
		if (user.role.slug !== GLOBAL_OWNER_ROLE.slug && !isWithinUsersLimit) {
			throw new ForbiddenError(RESPONSE_ERROR_MESSAGES.USERS_QUOTA_REACHED);
		}

		const token = this.issueJWT(user, usedMfa, browserId);
		const { samesite, secure } = this.globalConfig.auth.cookie;
		res.cookie(AUTH_COOKIE_NAME, token, {
			maxAge: this.jwtExpiration * Time.seconds.toMilliseconds,
			httpOnly: true,
			sameSite: samesite,
			secure,
		});
	}

	issueJWT(user: User, usedMfa: boolean = false, browserId?: string) {
		const payload: AuthJwtPayload = {
			id: user.id,
			hash: this.createJWTHash(user),
			browserId: browserId && this.hash(browserId),
			usedMfa,
		};
		return this.jwtService.sign(payload, {
			expiresIn: this.jwtExpiration,
		});
	}

	async resolveJwt(
		token: string,
		req: AuthenticatedRequest,
		res: Response,
	): Promise<[User, { usedMfa: boolean }]> {
		const jwtPayload: IssuedJWT = this.jwtService.verify(token, {
			algorithms: ['HS256'],
		});

		// TODO: Use an in-memory ttl-cache to cache the User object for upto a minute
		const user = await this.userRepository.findOne({
			where: { id: jwtPayload.id },
			relations: ['role'],
		});

		if (
			// If not user is found
			!user ||
			// or, If the user has been deactivated (i.e. LDAP users)
			user.disabled ||
			// or, If the email or password has been updated
			jwtPayload.hash !== this.createJWTHash(user)
		) {
			throw new AuthError('Unauthorized');
		}

		// Check if the token was issued for another browser session, ignoring the endpoints that can't send custom headers
		const endpoint = req.route ? `${req.baseUrl}${req.route.path}` : req.baseUrl;
		if (req.method === 'GET' && this.skipBrowserIdCheckEndpoints.includes(endpoint)) {
			this.logger.debug(`Skipped browserId check on ${endpoint}`);
		} else if (
			jwtPayload.browserId &&
			(!req.browserId || jwtPayload.browserId !== this.hash(req.browserId))
		) {
			this.logger.warn(`browserId check failed on ${endpoint}`);
			throw new AuthError('Unauthorized');
		}

		if (jwtPayload.exp * 1000 - Date.now() < this.jwtRefreshTimeout) {
			this.logger.debug('JWT about to expire. Will be refreshed');
			this.issueCookie(res, user, jwtPayload.usedMfa ?? false, req.browserId);
		}

		return [user, { usedMfa: jwtPayload.usedMfa ?? false }];
	}

	generatePasswordResetToken(user: User, expiresIn: TimeUnitValue = '20m') {
		const payload: PasswordResetToken = { sub: user.id, hash: this.createJWTHash(user) };
		return this.jwtService.sign(payload, { expiresIn });
	}

	generatePasswordResetUrl(user: User) {
		const instanceBaseUrl = this.urlService.getInstanceBaseUrl();
		const url = new URL(`${instanceBaseUrl}/change-password`);

		url.searchParams.append('token', this.generatePasswordResetToken(user));
		url.searchParams.append('mfaEnabled', user.mfaEnabled.toString());

		return url.toString();
	}

	async resolvePasswordResetToken(token: string): Promise<User | undefined> {
		let decodedToken: PasswordResetToken;
		try {
			decodedToken = this.jwtService.verify(token);
		} catch (e) {
			if (e instanceof TokenExpiredError) {
				this.logger.debug('Reset password token expired', { token });
			} else {
				this.logger.debug('Error verifying token', { token });
			}
			return;
		}

		const user = await this.userRepository.findOne({
			where: { id: decodedToken.sub },
			relations: ['authIdentities', 'role'],
		});

		if (!user) {
			this.logger.debug(
				'Request to resolve password token failed because no user was found for the provided user ID',
				{ userId: decodedToken.sub, token },
			);
			return;
		}

		if (decodedToken.hash !== this.createJWTHash(user)) {
			this.logger.debug('Password updated since this token was generated');
			return;
		}

		return user;
	}

	createJWTHash({ email, password, mfaEnabled, mfaSecret }: User) {
		const payload = [email, password];
		if (mfaEnabled && mfaSecret) {
			payload.push(mfaSecret.substring(0, 3));
		}
		return this.hash(payload.join(':')).substring(0, 10);
	}

	private hash(input: string) {
		return createHash('sha256').update(input).digest('base64');
	}

	/** How many **milliseconds** before expiration should a JWT be renewed. */
	get jwtRefreshTimeout() {
		const { jwtRefreshTimeoutHours, jwtSessionDurationHours } = this.globalConfig.userManagement;
		if (jwtRefreshTimeoutHours === 0) {
			return Math.floor(jwtSessionDurationHours * 0.25 * Time.hours.toMilliseconds);
		} else {
			return Math.floor(jwtRefreshTimeoutHours * Time.hours.toMilliseconds);
		}
	}

	/** How many **seconds** is an issued JWT valid for. */
	get jwtExpiration() {
		return this.globalConfig.userManagement.jwtSessionDurationHours * Time.hours.toSeconds;
	}
}
