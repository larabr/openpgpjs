import { webdriverLauncher } from '@web/test-runner-webdriver';
import wtrConfig from './web-test-runner.config.js';

export default {
  ...wtrConfig,
  browsers: [
    webdriverLauncher({
      protocol: 'http',
      hostname: '127.0.0.1',
      port: process.env.WEBDRIVER_PORT,
      path: '/',
      capabilities: {}
    })
  ]
};
