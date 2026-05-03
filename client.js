require(['api', 'alerts', 'translator'], function (api, alerts, translator) {
$(document).ready(function () {
	let cachedState = null;
	let pendingStateRequest = null;

	$(window).on('action:ajaxify.end', function () {
		cachedState = null;
		pendingStateRequest = null;

		injectNavbarRestoreItem();

		if (!isProfilePage()) {
			removeProfileMenuItems();
			return;
		}

		injectProfileMenuItems();
		setTimeout(injectProfileMenuItems, 200);
	});

	$(document).on('click', '.impersonate-users-login-link', async function (ev) {
		ev.preventDefault();

		const targetUid = parseInt($(this).attr('data-target-uid'), 10);
		if (!targetUid) {
			return;
		}

		try {
			const result = await api.post('/api/plugins/impersonate-users/switch', {
				targetUid: targetUid,
			});
			window.location.href = `${config.relative_path || ''}${result.next || '/'}`;
		} catch (err) {
			alerts.error(err);
		}
	});

	$(document).on('click', '.impersonate-users-restore-link', async function (ev) {
		ev.preventDefault();

		try {
			const result = await api.post('/api/plugins/impersonate-users/restore', {});
			window.location.href = `${config.relative_path || ''}${result.next || '/'}`;
		} catch (err) {
			alerts.error(err);
		}
	});

	// Inject "Return to original user" into the navbar user dropdown (#user-control-list)
	async function injectNavbarRestoreItem() {
		$('.impersonate-users-navbar-item').remove();
		$('.impersonate-users-navbar-divider').remove();

		const state = await getState().catch(() => null);
		if (!state || !state.isImpersonating) {
			return;
		}

		const userControlList = $('#user-control-list');
		if (!userControlList.length) {
			return;
		}

		const label = await translator.translate('[[impersonate-users:profile.restore-original]]');
		const html = `
			<li role="presentation" class="impersonate-users-navbar-item">
				<a class="dropdown-item rounded-1 d-flex align-items-center gap-2 impersonate-users-restore-link" href="#" role="menuitem">
					<i class="fa fa-undo fa-fw text-secondary"></i>
					<span>${label}</span>
				</a>
			</li>
			<li role="presentation" class="dropdown-divider impersonate-users-navbar-divider"></li>
		`;

		const logoutItem = userControlList.find('[component="user/logout"]').closest('li');
		if (logoutItem.length) {
			logoutItem.before(html);
		} else {
			userControlList.append(html);
		}
	}

	async function injectProfileMenuItems() {
		const state = await getState();
		if (!state || !state.canImpersonate) {
			removeProfileMenuItems();
			return;
		}

		const viewedUid = getViewedUid();
		if (!viewedUid) {
			removeProfileMenuItems();
			return;
		}

		const menu = ensureMenu();
		if (!menu.length) {
			return;
		}

		removeProfileMenuItems();

		const items = [];
		if (state.canImpersonate && viewedUid !== state.currentUid) {
			items.push(await buildLoginItem(viewedUid));
		}

		if (!items.length) {
			return;
		}

		menu.prepend(items.join(''));
		const insertedItems = menu.children('.impersonate-users-profile-item');
		const hasOtherItems = menu.children('li').not('.impersonate-users-profile-item, .impersonate-users-profile-divider').length > 0;
		if (hasOtherItems && insertedItems.length) {
			insertedItems.last().after('<li role="presentation" class="dropdown-divider impersonate-users-profile-divider"></li>');
		}
	}

	async function buildLoginItem(viewedUid) {
		const label = await translator.translate('[[impersonate-users:profile.login-as]]');
		return `
			<li role="presentation" class="impersonate-users-profile-item">
				<a class="dropdown-item rounded-1 d-flex align-items-center gap-2 impersonate-users-login-link" href="#" data-target-uid="${viewedUid}" role="menuitem">
					<i class="fa fa-user-secret fa-fw"></i>
					<span>${label}</span>
				</a>
			</li>
		`;
	}

	async function buildRestoreItem(state) {
		const label = await translator.translate('[[impersonate-users:profile.restore-original]]');
		const originalUid = state.impersonatorUid || '';
		return `
			<li role="presentation" class="impersonate-users-profile-item">
				<a class="dropdown-item rounded-1 d-flex align-items-center gap-2 impersonate-users-restore-link" href="#" data-original-uid="${originalUid}" role="menuitem">
					<i class="fa fa-undo fa-fw"></i>
					<span>${label}</span>
				</a>
			</li>
		`;
	}

	function ensureMenu() {
		let menu = $('.account-sub-links');
		if (menu.length) {
			return menu.first();
		}

		const container = $('.account .flex-shrink-0.d-flex.gap-1').first();
		const fallbackContainer = container.length ? container : $('.account .flex-shrink-0').first();

		if (!fallbackContainer.length) {
			return $();
		}

		const menuHtml = `
			<div class="btn-group bottom-sheet impersonate-users-menu">
				<button type="button" class="btn btn-light dropdown-toggle" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
					<i class="fa fa-gear fa-fw"></i>
				</button>
				<ul class="dropdown-menu dropdown-menu-end p-1 text-sm account-sub-links" role="menu"></ul>
			</div>
		`;

		fallbackContainer.append(menuHtml);
		menu = fallbackContainer.find('.account-sub-links').last();
		return menu;
	}

	function removeProfileMenuItems() {
		$('.impersonate-users-profile-item').remove();
		$('.impersonate-users-profile-divider').remove();
	}

	function isProfilePage() {
		const templateName = ajaxify && ajaxify.data && ajaxify.data.template ? ajaxify.data.template.name : '';
		return templateName.startsWith('account/') && $('.account').length > 0;
	}

	function getViewedUid() {
		const candidates = [
			ajaxify && ajaxify.data && ajaxify.data.uid,
			ajaxify && ajaxify.data && ajaxify.data.theirid,
			ajaxify && ajaxify.data && ajaxify.data.user && ajaxify.data.user.uid,
		];

		for (const value of candidates) {
			const uid = parseInt(value, 10);
			if (uid > 0) {
				return uid;
			}
		}

		return 0;
	}

	async function getState() {
		if (cachedState) {
			return cachedState;
		}

		if (!pendingStateRequest) {
			pendingStateRequest = api.get('/api/plugins/impersonate-users/privileges')
				.then((state) => {
					cachedState = state;
					return state;
				})
				.catch((err) => {
					pendingStateRequest = null;
					throw err;
				});
		}

		return await pendingStateRequest;
	}
});
});
