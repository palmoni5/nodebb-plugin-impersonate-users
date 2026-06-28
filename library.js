'use strict';

const winston = require.main.require('winston');

const user = require.main.require('./src/user');
const privileges = require.main.require('./src/privileges');
const routeHelpers = require.main.require('./src/routes/helpers');
const controllerHelpers = require.main.require('./src/controllers/helpers');
const authenticationController = require.main.require('./src/controllers/authentication');

const plugin = module.exports;

const IMPERSONATE_PRIVILEGE = 'impersonate:users';

plugin.init = async function ({ router, middleware }) {
	// Impersonation is performed exclusively through the CSRF-protected POST API below.
	// No GET page route is exposed, so a session switch cannot be triggered by a
	// cross-site link or navigation (CSRF).
	routeHelpers.setupApiRoute(router, 'get', '/api/plugins/impersonate-users/privileges', [middleware.ensureLoggedIn], getPrivileges);
	routeHelpers.setupApiRoute(router, 'post', '/api/plugins/impersonate-users/switch', [middleware.ensureLoggedIn, middleware.applyCSRF], switchApi);
	routeHelpers.setupApiRoute(router, 'post', '/api/plugins/impersonate-users/restore', [middleware.ensureLoggedIn, middleware.applyCSRF], restoreApi);
};

plugin.registerPrivileges = async function (data) {
	if (!data || !data.privileges || typeof data.privileges.set !== 'function') {
		return data;
	}

	data.privileges.set(IMPERSONATE_PRIVILEGE, {
		label: '[[impersonate-users:admin.impersonate-users]]',
		type: 'moderation',
	});

	return data;
};

async function getPrivileges(req, res) {
	const state = await getSessionState(req);
	await controllerHelpers.formatApiResponse(200, res, state);
}

async function switchApi(req, res) {
	const targetUid = parseInt(req.body && req.body.targetUid, 10);
	await switchToUid(req, targetUid);

	await controllerHelpers.formatApiResponse(200, res, {
		next: await getProfilePath(targetUid),
	});
}

async function restoreApi(req, res) {
	const restoredUid = await restoreOriginalUser(req);

	await controllerHelpers.formatApiResponse(200, res, {
		next: await getProfilePath(restoredUid),
	});
}

async function switchToUid(req, targetUid) {
	if (!Number.isInteger(targetUid) || targetUid <= 0) {
		throw new Error('[[error:no-user]]');
	}

	const exists = await user.exists(targetUid);
	if (!exists) {
		throw new Error('[[error:no-user]]');
	}

	const state = await getSessionState(req);
	if (!state.canImpersonate) {
		throw new Error('[[error:no-privileges]]');
	}

	if (state.isImpersonating && targetUid === state.actorUid) {
		return await restoreOriginalUser(req);
	}

	if (targetUid === state.currentUid) {
		return targetUid;
	}

	await revokeCurrentSession(req);
	req.session.forceLogin = true;
	await authenticationController.doLogin(req, targetUid);

	req.session.impersonatorUid = state.actorUid;
	await saveSession(req);

	winston.info(`[nodebb-plugin-impersonate-users] ${state.actorUid} is now impersonating ${targetUid}`);
	return targetUid;
}

async function restoreOriginalUser(req) {
	const originalUid = parseInt(req.session && req.session.impersonatorUid, 10);
	if (!originalUid) {
		throw new Error('[[error:no-privileges]]');
	}

	const exists = await user.exists(originalUid);
	if (!exists) {
		throw new Error('[[error:no-user]]');
	}

	await revokeCurrentSession(req);
	req.session.forceLogin = true;
	await authenticationController.doLogin(req, originalUid);

	delete req.session.impersonatorUid;
	await saveSession(req);

	winston.info(`[nodebb-plugin-impersonate-users] Restored impersonated session back to ${originalUid}`);
	return originalUid;
}

async function getSessionState(req) {
	const currentUid = parseInt(req.uid, 10) || 0;
	const impersonatorUid = parseInt(req.session && req.session.impersonatorUid, 10) || 0;
	const actorUid = impersonatorUid || currentUid;
	const canImpersonateUsers = actorUid > 0 ? await canImpersonate(actorUid) : false;

	return {
		canImpersonate: canImpersonateUsers,
		isImpersonating: Boolean(impersonatorUid && impersonatorUid !== currentUid),
		currentUid,
		actorUid,
		impersonatorUid: impersonatorUid || null,
	};
}

async function canImpersonate(uid) {
	if (!uid) {
		return false;
	}

	const [isAdmin, hasPrivilege] = await Promise.all([
		user.isAdministrator(uid),
		privileges.global.can(IMPERSONATE_PRIVILEGE, uid),
	]);

	return Boolean(isAdmin || hasPrivilege);
}

async function revokeCurrentSession(req) {
	if (!req.sessionID || !req.uid || parseInt(req.uid, 10) <= 0) {
		return;
	}

	await user.auth.revokeSession(req.sessionID, req.uid);
}

async function getProfilePath(uid) {
	const userslug = await user.getUserField(uid, 'userslug');
	return userslug ? `/user/${userslug}` : '/';
}

async function saveSession(req) {
	await new Promise((resolve, reject) => {
		req.session.save((err) => {
			if (err) {
				reject(err);
				return;
			}

			resolve();
		});
	});
}
