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
    jsonOutput: core.getBooleanInput('json-output'),
    allowDirty: core.getBooleanInput('allow-dirty'),
    failOnCVSS: parseFloat(core.getInput('fail-on-cvss')) || 10,
    path: core.getInput('path',{trimWhitespace: true}) || '.',
    debug: core.getBooleanInput('debug'),
    "skip-vms": core.getBooleanInput('skip-vms'),
    "no-graphs": core.getBooleanInput('no-graphs'),
    recursive: core.getBooleanInput('recursive'),
    "skip-collectors": core.getInput('skip-collectors').split(','),
    "scan-collectors": core.getInput('scan-collectors').split(','),
    platformType: core.getInput('platformType'),
    breakBuildOnPolicyFindings: core.getInput('breakBuildOnPolicyFindings'),
    scaFixEnabled: core.getBooleanInput('sca_fix_enabled'),
    profileName: core.getInput('profile_name'),
    prNumber: parseInt(core.getInput('pr_number'), 10)
}

try {
    runAction(options);
} catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
}