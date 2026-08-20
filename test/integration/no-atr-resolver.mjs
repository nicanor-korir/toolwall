/**
 * A module-resolution hook that makes `agent-threat-rules` unresolvable, exactly as it is on a
 * machine that ran `npm install --omit=optional`.
 *
 * `test/integration/optional-dep-absent.test.ts` needs to observe the not-installed path, and the
 * package IS installed in this repo's `node_modules`. Uninstalling it to run one test is not an
 * option in a shared tree, and asserting on a mocked rejection would only prove the mock works.
 * This hook makes the real `await import("agent-threat-rules")` in `src/guards/metadata/rules.ts`
 * fail with the real `ERR_MODULE_NOT_FOUND` that Node raises, inside a real CLI child process.
 *
 * The error is constructed to match Node's own: `npm ls` reports `ERR_MODULE_NOT_FOUND` with a
 * `Cannot find package` message, and the code under test formats `error.message` into its
 * explanation, so a divergence here would make the test assert on text users never see.
 *
 * In CI's `optional-dep-absent` job the package is genuinely absent and this hook is a harmless
 * no-op — the same test therefore covers both the simulated and the real absence.
 */
export async function resolve(specifier, context, nextResolve) {
    if (specifier === 'agent-threat-rules' || specifier.startsWith('agent-threat-rules/')) {
        const error = new Error(
            `Cannot find package 'agent-threat-rules' imported from ${context.parentURL ?? '<unknown>'}`
        );
        error.code = 'ERR_MODULE_NOT_FOUND';
        throw error;
    }
    return nextResolve(specifier, context);
}
