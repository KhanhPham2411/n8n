import { z } from 'zod';
import { Z } from 'zod-class';

export class LoginRequestDto extends Z.class({
	/*
	 * The LDAP username does not need to be an email, so email validation
	 * is not enforced here. The controller determines whether this is an
	 * email and validates when LDAP is disabled
	 * These fields are optional to support N8N_LOCAL mode auto-login
	 */
	emailOrLdapLoginId: z.string().trim().optional(),
	password: z.string().min(1).optional(),
	mfaCode: z.string().optional(),
	mfaRecoveryCode: z.string().optional(),
}) {}
