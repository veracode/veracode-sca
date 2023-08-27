#!/usr/bin/env node

import * as core from '@actions/core'
import { Options } from "./options";
import {runAction} from './srcclr';

const options: Options = {
    quick: core.getBooleanInput('quick'),
    updateAdvisor: core.getBooleanInput('update_advisor'),
    minCVSSForIssue: parseFloat(core.getInput('min-cvss-for-issue')) || 0,
    url: core.getInput('url'),
    github_token: core.getInput('github_token',{required:true}),
    createIssues: core.getBooleanInput('create-issues'),
    allowDirty: core.getBooleanInput('allow-dirty'),
    failOnCVSS: parseFloat(core.getInput('fail-on-cvss')) || 10,
    path: core.getInput('path',{trimWhitespace: true}) || '.',
    debug: core.getBooleanInput('debug'),
    "skip-vms": core.getBooleanInput('skip-vms'),
    "no-graphs": core.getBooleanInput('no-graphs'),
    recursive: core.getBooleanInput('recursive'),
    "skip-collectors": core.getInput('skip-collectors').split(','),
    workspace_automation: core.getBooleanInput('workspace_automation'),
    VID: core.getInput('VID'),
    VKEY: core.getInput('VKEY')
}

runAction(options);