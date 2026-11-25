import { defineConfig } from 'vitest/config';

// node:sqlite: flag exigido no Node 22.5-23.3; removido a partir do 23.4.
const [major, minor] = process.versions.node.split('.').map(Number);
const needFlag = (major === 22 && minor >= 5) || (major === 23 && minor < 4);

export default defineConfig({
  test: {
    pool: 'forks',
    poolOptions: {
      forks: { execArgv: needFlag ? ['--experimental-sqlite'] : [] },
    },
  },
});
