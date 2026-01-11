<script setup lang="ts">
// [IMPROVED AUTH] Restored logout functionality for browser users
import { VIEWS } from '@/app/constants';
import { useUsersStore } from '@/features/settings/users/users.store';
import { useToast } from '@/app/composables/useToast';
import { useRouter } from 'vue-router';
import { useI18n } from '@n8n/i18n';
import { onMounted } from 'vue';

const usersStore = useUsersStore();
const toast = useToast();
const router = useRouter();
const i18n = useI18n();

const logout = async () => {
	try {
		console.debug('[IMPROVED AUTH] Performing logout');
		await usersStore.logout();
		console.debug('[IMPROVED AUTH] Logout successful, redirecting to signin');
		window.location.href = router.resolve({ name: VIEWS.SIGNIN }).href;
	} catch (e) {
		console.error('[IMPROVED AUTH] Logout failed:', e);
		toast.showError(e, i18n.baseText('auth.signout.error'));
	}
};

onMounted(() => {
	void logout();
});
</script>

<template>
	<div />
</template>
