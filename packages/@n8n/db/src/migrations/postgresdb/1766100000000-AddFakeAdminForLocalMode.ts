import { GlobalConfig } from '@n8n/config';
import { Container } from '@n8n/di';
import { v4 as uuid } from 'uuid';

import type { IrreversibleMigration, MigrationContext } from '../migration-types';

/**
 * Add fake admin user (admin@n8n.local) when N8N_LOCAL=true for local development.
 * This user is verified, has admin role, and can be used for local testing.
 */
export class AddFakeAdminForLocalMode1766100000000 implements IrreversibleMigration {
	async up({ escape, runQuery, logger, migrationName }: MigrationContext) {
		const globalConfig = Container.get(GlobalConfig);

		// Only run this migration if N8N_LOCAL is enabled
		if (!globalConfig.license.isLocal) {
			logger.info(`[${migrationName}] N8N_LOCAL is not enabled, skipping`);
			return;
		}

		const userTable = escape.tableName('user');
		const roleTable = escape.tableName('role');
		const email = escape.columnName('email');
		const adminEmail = globalConfig.license.localAdminEmail;

		// Check if local admin user already exists
		const existingUser: Array<{ id: string }> = await runQuery(
			`SELECT id FROM ${userTable} WHERE ${email} = '${adminEmail}'`,
		);

		if (existingUser.length > 0) {
			logger.info(`[${migrationName}] User ${adminEmail} already exists, skipping`);
			return;
		}

		// Get the global:admin role slug
		const adminRole: Array<{ slug: string }> = await runQuery(
			`SELECT ${escape.columnName('slug')} FROM ${roleTable} WHERE ${escape.columnName('slug')} = 'global:admin' LIMIT 1`,
		);

		if (adminRole.length === 0) {
			logger.error(`[${migrationName}] global:admin role not found, skipping`);
			return;
		}

		const userId = uuid();
		// Pre-hashed password for "password" using bcrypt with rounds=10
		// This is the same hash used in tests
		const passwordHash = '$2a$10$njedH7S6V5898mj6p0Jr..IGY9Ms.qNwR7RbSzzX9yubJocKfvGGK';

		// Insert the fake admin user
		await runQuery(
			`INSERT INTO ${userTable} (
				${escape.columnName('id')},
				${escape.columnName('email')},
				${escape.columnName('firstName')},
				${escape.columnName('lastName')},
				${escape.columnName('password')},
				${escape.columnName('roleSlug')},
				${escape.columnName('disabled')},
				${escape.columnName('mfaEnabled')},
				${escape.columnName('createdAt')},
				${escape.columnName('updatedAt')}
			) VALUES (
				'${userId}',
				'${adminEmail}',
				'Admin',
				'Local',
				'${passwordHash}',
				'global:admin',
				false,
				false,
				CURRENT_TIMESTAMP,
				CURRENT_TIMESTAMP
			)`,
		);

		logger.info(
			`[${migrationName}] Created fake admin user: ${adminEmail} with password: password`,
		);
	}
}
