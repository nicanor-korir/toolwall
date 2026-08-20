/**
 * `--import` entry point that installs `no-atr-resolver.mjs` before any user code loads.
 * See that file for why the absence is simulated rather than arranged by uninstalling.
 */
import { register } from 'node:module';

register('./no-atr-resolver.mjs', import.meta.url);
