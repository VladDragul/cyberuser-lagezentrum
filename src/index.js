// Worker entry point for the homepage brief and the /news redirect.
//
// workerd treats every named export of the main module as an entrypoint and
// only accepts functions, classes or handler objects there. This module must
// therefore keep a default export only; all logic and constants live in
// worker.js, where the tests import them from.

import { handleRequest, runCron } from './worker.js';

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
  async scheduled(controller, env) {
    await runCron(controller.scheduledTime, env);
  },
};
