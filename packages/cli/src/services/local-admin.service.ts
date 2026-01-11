import { Logger } from '@n8n/backend-common';
import { GlobalConfig } from '@n8n/config';
import {
	GLOBAL_OWNER_ROLE,
	UserRepository,
	ProjectRepository,
	ProjectRelationRepository,
} from '@n8n/db';
import { Service } from '@n8n/di';
import { PROJECT_OWNER_ROLE_SLUG } from '@n8n/permissions';

import { PasswordUtility } from '@/services/password.utility';

/**
 * Service responsible for ensuring the N8N_LOCAL admin user exists
 * when running in local development mode (N8N_LOCAL=true)
 */
@Service()
export class LocalAdminService {
	constructor(
		private readonly logger: Logger,
		private readonly globalConfig: GlobalConfig,
		private readonly userRepository: UserRepository,
		private readonly passwordUtility: PasswordUtility,
		private readonly projectRepository: ProjectRepository,
		private readonly projectRelationRepository: ProjectRelationRepository,
	) {}

	/**
	 * Ensures the local admin user exists when N8N_LOCAL mode is enabled
	 * Creates or updates the user with the configured email
	 */
	async ensureLocalAdminExists(): Promise<void> {
		if (!this.globalConfig.license.isLocal) {
			this.logger.info('N8N_LOCAL mode is disabled, skipping local admin creation');
			return;
		}

		const localAdminEmail = this.globalConfig.license.localAdminEmail;
		this.logger.info(
			`N8N_LOCAL mode enabled, ensuring local admin user exists: ${localAdminEmail}`,
		);

		try {
			// Check if the local admin user already exists
			const localAdmin = await this.userRepository.findOne({
				where: { email: localAdminEmail },
				relations: ['role'],
			});

			if (localAdmin) {
				this.logger.info(`Local admin user ${localAdminEmail} already exists`);
				// Ensure personal project exists for this user
				await this.ensurePersonalProjectExists(localAdmin);
				return;
			}

			// Check if there's already an owner - if yes, update their email to the local admin email
			const existingOwner = await this.userRepository.findOne({
				where: { role: { slug: GLOBAL_OWNER_ROLE.slug } },
				relations: ['role'],
			});

			if (existingOwner) {
				// Update existing owner to use the local admin email
				existingOwner.email = localAdminEmail;
				existingOwner.firstName = existingOwner.firstName || 'Admin';
				existingOwner.lastName = existingOwner.lastName || 'User';

				// Set a default password if not set (for shell users)
				existingOwner.password ??= await this.passwordUtility.hash('admin');

				await this.userRepository.save(existingOwner);
				this.logger.info(
					`Updated existing owner user to use local admin email: ${localAdminEmail}`,
				);
				// Ensure personal project exists for this user
				await this.ensurePersonalProjectExists(existingOwner);
			} else {
				// No owner exists yet - create the local admin user
				const newAdmin = this.userRepository.create({
					email: localAdminEmail,
					firstName: 'Admin',
					lastName: 'User',
					password: await this.passwordUtility.hash('admin'),
					role: { slug: GLOBAL_OWNER_ROLE.slug },
				});

				await this.userRepository.createUserWithProject(newAdmin);
				this.logger.info(`Created local admin user: ${localAdminEmail}`);
			}
		} catch (error) {
			this.logger.error(`Failed to ensure local admin user exists: ${(error as Error).message}`, {
				email: localAdminEmail,
				error: error as Error,
			});
		}
	}

	/**
	 * Ensures that a personal project exists for the given user
	 * Creates the project and relation if they don't exist
	 */
	private async ensurePersonalProjectExists(user: {
		id: string;
		email: string;
		firstName?: string | null;
		lastName?: string | null;
	}): Promise<void> {
		// Check if personal project already exists
		const existingProject = await this.projectRepository.getPersonalProjectForUser(user.id);

		if (existingProject) {
			this.logger.debug(`Personal project already exists for user ${user.email}`);
			return;
		}

		this.logger.info(`Creating personal project for user ${user.email}`);

		try {
			// Create personal project
			const personalProjectName = `${user.firstName ?? user.email}'s Projects`;
			const project = this.projectRepository.create({
				type: 'personal',
				name: personalProjectName,
				creatorId: user.id,
			});
			const savedProject = await this.projectRepository.save(project);

			// Create project relation
			const projectRelation = this.projectRelationRepository.create({
				projectId: savedProject.id,
				userId: user.id,
				role: { slug: PROJECT_OWNER_ROLE_SLUG },
			});
			await this.projectRelationRepository.save(projectRelation);

			this.logger.info(`Successfully created personal project for user ${user.email}`);
		} catch (error) {
			this.logger.error(
				`Failed to create personal project for user ${user.email}: ${(error as Error).message}`,
				{
					userId: user.id,
					error: error as Error,
				},
			);
			throw error;
		}
	}
}
