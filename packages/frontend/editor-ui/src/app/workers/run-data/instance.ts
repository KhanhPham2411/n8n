import * as Comlink from 'comlink';
import type { RunDataWorker } from '@/app/workers/run-data/worker';

import Worker from './worker?worker&inline';

const worker = new Worker();

export const runDataWorker = Comlink.wrap<RunDataWorker>(worker);
