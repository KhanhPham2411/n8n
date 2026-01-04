import type { RequestHandler } from 'express';
import { inDevelopment } from '@n8n/backend-common';

export const corsMiddleware: RequestHandler = (req, res, next) => {
	if ('origin' in req.headers) {
		const origin = req.headers.origin as string;

		// Always allow VS Code webview origins (for VS Code extensions)
		// VS Code webviews use origins like: vscode-webview://...
		const isVSCodeWebview = origin?.startsWith('vscode-webview://');

		// Allow CORS if:
		// 1. It's a VS Code webview (always allowed for VS Code extensions)
		// 2. It's development mode (original behavior)
		if (isVSCodeWebview || inDevelopment) {
			res.header('Access-Control-Allow-Origin', origin);
			res.header('Access-Control-Allow-Credentials', 'true');
			res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
			res.header(
				'Access-Control-Allow-Headers',
				'Origin, X-Requested-With, Content-Type, Accept, push-ref, browser-id, anonymousid, authorization',
			);
		}
	}

	if (req.method === 'OPTIONS') {
		res.writeHead(204).end();
	} else {
		next();
	}
};
