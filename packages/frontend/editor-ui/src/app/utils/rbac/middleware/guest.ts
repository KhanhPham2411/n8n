import type { RouterMiddleware } from '@/app/types/router';
import { VIEWS } from '@/app/constants';
import type { GuestPermissionOptions } from '@/app/types/rbac';
import { isGuest } from '@/app/utils/rbac/checks';

// [IMPROVED AUTH] Guest middleware - only allows unauthenticated users to access signin/signup pages
export const guestMiddleware: RouterMiddleware<GuestPermissionOptions> = async (
	to,
	_from,
	next,
) => {
	// [IMPROVED AUTH] Check if user is a guest (not authenticated)
	const valid = isGuest();
	console.debug('[IMPROVED AUTH] Guest middleware check - isGuest:', valid, 'route:', to.path);

	if (!valid) {
		// User is authenticated, redirect away from guest-only pages
		const redirect = (to.query.redirect as string) ?? '';

		// Allow local path redirects
		if (redirect.startsWith('/')) {
			console.debug('[IMPROVED AUTH] Authenticated user - redirecting to:', redirect);
			return next(redirect);
		}

		try {
			// Only allow origin domain redirects
			const url = new URL(redirect);
			if (url.origin === window.location.origin) {
				console.debug('[IMPROVED AUTH] Authenticated user - redirecting to URL:', redirect);
				return next(redirect);
			}
		} catch {
			// Intentionally fall through to redirect to homepage
			// if the redirect is an invalid URL
		}

		console.debug('[IMPROVED AUTH] Authenticated user - redirecting to homepage');
		return next({ name: VIEWS.HOMEPAGE });
	}

	// User is a guest, allow access to signin/signup pages
	console.debug('[IMPROVED AUTH] Guest user - allowing access to:', to.path);
};
