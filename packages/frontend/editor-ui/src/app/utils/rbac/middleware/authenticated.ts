import type { RouterMiddleware } from '@/app/types/router';
import { VIEWS } from '@/app/constants';
import type { AuthenticatedPermissionOptions } from '@/app/types/rbac';
import { isAuthenticated, shouldEnableMfa } from '@/app/utils/rbac/checks';

// [IMPROVED AUTH] Restored authentication middleware - redirects to /signin for browser requests
export const authenticatedMiddleware: RouterMiddleware<AuthenticatedPermissionOptions> = async (
	to,
	_from,
	next,
	options,
) => {
	// [IMPROVED AUTH] Log authentication check
	console.debug('[IMPROVED AUTH] Checking authentication for route:', to.path);

	// Ensure we remove existing redirect query parameter to avoid infinite loops
	const url = new URL(window.location.href);
	url.searchParams.delete('redirect');
	const redirect = to.query.redirect ?? encodeURIComponent(`${url.pathname}${url.search}`);

	const valid = isAuthenticated(options);
	if (!valid) {
		// [IMPROVED AUTH] User not authenticated - redirecting to signin
		console.debug('[IMPROVED AUTH] User not authenticated, redirecting to signin');
		return next({ name: VIEWS.SIGNIN, query: { redirect } });
	}

	// If MFA is not enabled, and the instance enforces MFA, redirect to personal settings
	const mfaNeeded = shouldEnableMfa();
	if (mfaNeeded) {
		console.debug('[IMPROVED AUTH] MFA required, checking if user needs to enable it');
		if (to.name !== VIEWS.PERSONAL_SETTINGS) {
			return next({ name: VIEWS.PERSONAL_SETTINGS, query: { redirect } });
		}
		return;
	}

	console.debug('[IMPROVED AUTH] User authenticated, allowing access');
};
