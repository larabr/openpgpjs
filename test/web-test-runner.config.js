import { browserstackLauncher } from '@web/test-runner-browserstack';
import { playwrightLauncher } from '@web/test-runner-playwright';

const sharedBrowserstackCapabilities = {
  'browserstack.user': process.env.BROWSERSTACK_USERNAME,
  'browserstack.key': process.env.BROWSERSTACK_ACCESS_KEY,

  project: `openpgpjs/${process.env.GITHUB_EVENT_NAME || 'push'}${process.env.LIGHTWEIGHT ? '/lightweight' : ''}`,
  name: process.env.GITHUB_WORKFLOW || 'local',
  build: process.env.GITHUB_SHA || 'local',
  timeout: 450,
  acceptSslCerts: true,
  'browserstack.acceptInsecureCerts': true,
};

const sharedPlaywrightCIOptions = {
  createBrowserContext: ({ browser, config }) => browser.newContext({ ignoreHTTPSErrors: true }),
  headless: true
}

export default {
  nodeResolve: true, // to resolve npm module imports in `unittests.html`
  files: './test/unittests.html',
  protocol: 'https:',
  hostname: '127.0.0.1',
  http2: true,
  sslKey: './127.0.0.1-key.pem',
  sslCert: './127.0.0.1.pem',
  testsStartTimeout: 120000,
  browserStartTimeout: 120000,
  testsFinishTimeout: 450000,
  concurrency: 1,
  groups: [
    { name: 'local' }, // group meant to be used with either --browser or --manual options via CLI
    {
      name: 'headless:ci',
      browsers: [
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'chromium'
        }),
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'firefox'
        }),
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'webkit'
        })
      ]
    },
    {
      name: 'browserstack',
      browsers: process.env.BROWSERSTACK_USERNAME && [
        browserstackLauncher({
          capabilities: {
            ...sharedBrowserstackCapabilities,
            browserName: 'Safari',
            browser_version: 'latest', // Webkit and Safari can differ in behavior
            os: 'OS X',
            os_version: 'Ventura'
          }
        }),
        browserstackLauncher({
          capabilities: {
            ...sharedBrowserstackCapabilities,
            browserName: 'Safari',
            browser_version: '14', // min supported version
            os: 'OS X',
            os_version: 'Big Sur'
          }
        }),
        browserstackLauncher({
          capabilities: {
            ...sharedBrowserstackCapabilities,
            device: 'iPhone 12',
            real_mobile: true,
            os: 'ios',
            os_version: '14'
          }
        })
      ]
    }
  ]
};
