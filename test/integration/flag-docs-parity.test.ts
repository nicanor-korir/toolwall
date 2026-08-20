/**
 * **Documentation drift is a support burden, so it is a test failure.**
 *
 * A release audit found the README documenting 11 of the CLI's 28 flags. Nothing was *wrong* —
 * every documented spelling existed — but `--tier`, `--pins`, `--on-unverifiable`, `--no-guards`
 * and thirteen others existed only in `--help`. Two of those are load-bearing for claims the
 * README makes elsewhere: the false-positive tables are indexed by tier and never name `--tier`,
 * and the pin-store section gives a path without saying it is relocatable. That is the shape of
 * drift that generates support questions, and it recurs silently unless something checks.
 *
 * So this file checks both directions, and both directions matter for different reasons:
 *
 *   - **Documented but not implemented** is the severe one. A user types what the README says and
 *     gets `unknown option`. First-run failure, and a trust problem.
 *   - **Implemented but not documented** is the quiet one. The feature exists, nobody finds it,
 *     and it may as well not have shipped.
 *
 * It reads `src/cli/args.ts` as TEXT rather than importing the parser, deliberately: the parser
 * exposes no list of accepted flags, and adding one purely for a test would put the test's answer
 * key inside the thing under test. The `case` labels of `parseArgs`'s switch ARE the accepted set
 * — the `default` arm hard-errors — so scraping them is reading the truth, not a restatement.
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(here, '../..');
const ARGS = path.join(REPO, 'src/cli/args.ts');
const README = path.join(REPO, 'README.md');

/** The heading that opens the flag reference table in the README. */
const TABLE_HEADING = '#### Every flag';

/**
 * Flags that the parser accepts but the reference table intentionally omits.
 *
 * Empty, and it should stay that way — an entry here is a promise that a user who reads the
 * README and then types the flag will still be surprised. If something genuinely must be hidden,
 * it needs a reason written next to it.
 */
const INTENTIONALLY_UNDOCUMENTED = new Set<string>([]);

async function acceptedFlags(): Promise<Set<string>> {
    const source = await readFile(ARGS, 'utf8');
    const flags = new Set<string>();
    // `case '--foo':` / `case '-h':`, single or double quoted, with or without a trailing brace.
    for (const match of source.matchAll(/case\s+['"](-{1,2}[a-zA-Z][a-zA-Z0-9-]*)['"]\s*:/gu)) {
        flags.add(match[1] as string);
    }
    return flags;
}

async function documentedFlags(): Promise<Set<string>> {
    const readme = await readFile(README, 'utf8');
    const start = readme.indexOf(TABLE_HEADING);
    expect(start, `README no longer contains a "${TABLE_HEADING}" section`).toBeGreaterThan(-1);

    // The table runs until the next heading at the same or higher level.
    const rest = readme.slice(start + TABLE_HEADING.length);
    const end = rest.search(/\n#{1,4} /u);
    const table = end === -1 ? rest : rest.slice(0, end);

    const flags = new Set<string>();
    for (const line of table.split('\n')) {
        if (!line.startsWith('|')) continue;
        const firstCell = line.split('|')[1] ?? '';
        // A row may document an alias pair: `-v`, `--verbose`
        for (const match of firstCell.matchAll(/`(-{1,2}[a-zA-Z][a-zA-Z0-9-]*)`/gu)) {
            flags.add(match[1] as string);
        }
    }
    return flags;
}

describe('README flag reference matches the parser', () => {
    it('scrapes a plausible number of flags from both sides', async () => {
        // Guard the guard: if either regex silently stopped matching, every assertion below would
        // pass against two empty sets and prove nothing.
        const accepted = await acceptedFlags();
        const documented = await documentedFlags();
        expect(accepted.size, 'scraped no flags from args.ts — the case-label regex has drifted').toBeGreaterThan(20);
        expect(documented.size, 'scraped no flags from the README table — its format has drifted').toBeGreaterThan(20);
    });

    it('documents no flag that the parser does not accept', async () => {
        const accepted = await acceptedFlags();
        const documented = await documentedFlags();
        const phantom = [...documented].filter(f => !accepted.has(f)).sort();
        expect(
            phantom,
            'The README documents flags that src/cli/args.ts does not accept. A user who types one of ' +
                'these gets "unknown option" on their first run. Fix the README, or implement the flag.'
        ).toEqual([]);
    });

    it('documents every flag the parser accepts', async () => {
        const accepted = await acceptedFlags();
        const documented = await documentedFlags();
        const undocumented = [...accepted]
            .filter(f => !documented.has(f) && !INTENTIONALLY_UNDOCUMENTED.has(f))
            .sort();
        expect(
            undocumented,
            `These flags exist in src/cli/args.ts but appear nowhere in the README's "${TABLE_HEADING}" ` +
                'table. A feature nobody can find has not shipped. Add a row, or add the flag to ' +
                'INTENTIONALLY_UNDOCUMENTED with a reason.'
        ).toEqual([]);
    });

    it('lists every documented flag in --help too, so the two sources agree', async () => {
        // `--help` is what a user reaches for when the README is not in front of them. A flag
        // documented in one place and not the other is still drift, just a cheaper kind.
        const source = await readFile(ARGS, 'utf8');
        const usageStart = source.indexOf('const USAGE');
        expect(usageStart, 'args.ts no longer defines USAGE').toBeGreaterThan(-1);
        const usage = source.slice(usageStart, source.indexOf('parseArgs'));

        const documented = await documentedFlags();
        const missingFromUsage = [...documented].filter(f => !usage.includes(f)).sort();
        expect(
            missingFromUsage,
            'These flags are in the README table but not in the USAGE text that --help prints.'
        ).toEqual([]);
    });
});
