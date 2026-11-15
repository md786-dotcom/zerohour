import { defineConfig } from '@playwright/test';

// One sensor process with one state dir: the demo steps share state, so tests run in order on one worker.
export default defineConfig({
  testDir: './tests',
  workers: 1,
  fullyParallel: false,
  retries: 0,
  outputDir: 'artifacts/test-results',
  reporter: [
    ['list'],
    ['html', { outputFolder: 'artifacts/report', open: 'never' }],
    ['json', { outputFile: 'artifacts/results.json' }],
  ],
  use: {
    baseURL: 'http://127.0.0.1:8799',
    trace: 'on',
    video: 'on',
    screenshot: 'on',
  },
  webServer: {
    command: 'rm -rf .state && ../build/zerohour serve --port 8799 --state .state -c ../zerohour.conf',
    url: 'http://127.0.0.1:8799/api/state',
    reuseExistingServer: false,
    timeout: 15_000,
  },
});
