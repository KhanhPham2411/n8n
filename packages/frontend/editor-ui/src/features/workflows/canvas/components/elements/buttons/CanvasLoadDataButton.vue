<script setup lang="ts">
import { useI18n } from '@n8n/i18n';
import { computed, ref, onMounted } from 'vue';
import { N8nActionDropdown, N8nButton, N8nText, type ActionDropdownItem } from '@n8n/design-system';
import { useWorkflowFileSync } from '@/app/composables/useWorkflowFileSync';
import { useToast } from '@/app/composables/useToast';

const emit = defineEmits<{
	load: [filePath: string];
}>();

const props = defineProps<{
	disabled?: boolean;
	size?: 'small' | 'medium' | 'large';
}>();

const i18n = useI18n();
const toast = useToast();
const { requestListDataFiles, requestLoadDataFile } = useWorkflowFileSync();

const dataFiles = ref<Array<{ path: string; name: string }>>([]);
const selectedDataFile = ref<string | undefined>(undefined);
const isLoading = ref(false);

const label = computed(() => {
	return i18n.baseText('nodeView.loadData.button');
});

const actions = computed(() =>
	dataFiles.value.map<ActionDropdownItem<string>>((file) => ({
		label: file.name,
		disabled: props.disabled || isLoading.value,
		id: file.path,
		checked: selectedDataFile.value === file.path,
	})),
);

const isSplitButton = computed(() => dataFiles.value.length > 1);

async function loadDataFiles() {
	if (isLoading.value) return;

	isLoading.value = true;
	try {
		const files = await requestListDataFiles();
		dataFiles.value = files || [];

		// If there's only one file, select it automatically
		if (dataFiles.value.length === 1) {
			selectedDataFile.value = dataFiles.value[0].path;
		}
	} catch (error) {
		console.error('[CanvasLoadDataButton] Failed to load data files:', error);
		toast.showError(
			error instanceof Error ? error : new Error(String(error)),
			'Failed to list data files',
		);
	} finally {
		isLoading.value = false;
	}
}

async function onLoadData(filePath?: string) {
	const pathToLoad = filePath || selectedDataFile.value || dataFiles.value[0]?.path;
	if (!pathToLoad) {
		if (dataFiles.value.length === 0) {
			toast.showError(new Error('No data files found'), 'No data files available');
		}
		return;
	}

	if (isLoading.value) return;

	isLoading.value = true;
	try {
		await requestLoadDataFile(pathToLoad);
		selectedDataFile.value = pathToLoad;
		emit('load', pathToLoad);
	} catch (error) {
		console.error('[CanvasLoadDataButton] Failed to load data file:', error);
		toast.showError(
			error instanceof Error ? error : new Error(String(error)),
			'Failed to load data file',
		);
	} finally {
		isLoading.value = false;
	}
}

function onSelectDataFile(filePath: string) {
	selectedDataFile.value = filePath;
	onLoadData(filePath);
}

onMounted(() => {
	loadDataFiles();
});
</script>

<template>
	<div :class="[$style.component, isSplitButton ? $style.split : '']">
		<N8nButton
			:class="$style.button"
			:loading="isLoading"
			:disabled="disabled"
			:size="size ?? 'large'"
			icon="folder-open"
			type="secondary"
			data-test-id="load-data-button"
			@click="onLoadData()"
		>
			{{ label }}
		</N8nButton>
		<template v-if="isSplitButton">
			<div role="presentation" :class="$style.divider" />
			<N8nActionDropdown
				:class="$style.menu"
				:items="actions"
				:disabled="disabled || isLoading"
				placement="top"
				:extra-popper-class="$style.menuPopper"
				@select="onSelectDataFile"
			>
				<template #activator>
					<N8nButton
						type="secondary"
						icon-size="large"
						:disabled="disabled || isLoading"
						:class="$style.chevron"
						aria-label="Select data file"
						icon="chevron-down"
					/>
				</template>
				<template #menuItem="item">
					<div :class="[$style.menuItem, item.disabled ? $style.disabled : '']">
						<N8nText bold size="small">{{ item.label }}</N8nText>
					</div>
				</template>
			</N8nActionDropdown>
		</template>
	</div>
</template>

<style lang="scss" module>
.component {
	position: relative;
	display: flex;
	align-items: stretch;
}

.button {
	.split & {
		height: var(--spacing--2xl);

		padding-inline-start: var(--spacing--xs);
		padding-block: 0;
		border-top-right-radius: 0;
		border-bottom-right-radius: 0;
	}
}

.divider {
	width: 1px;
	background-color: var(--button--color--text, var(--button--color--text--secondary));
}

.chevron {
	width: 40px;
	border-top-left-radius: 0;
	border-bottom-left-radius: 0;
}

.menu :global(.el-dropdown) {
	height: 100%;
}

.menuPopper {
	// Width upper bound is enforced by char count instead
	max-width: none !important;
}

.menuItem {
	display: flex;
	align-items: center;
	gap: var(--spacing--2xs);
}

.menuItem.disabled {
	opacity: 0.5;
}
</style>
