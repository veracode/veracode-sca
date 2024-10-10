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
    "skip-collectors": core.getInput('skip-collectors').split(',')
    
}

//we dont need a proxy for the artifact upload
// Store current proxy environment variables
const httpProxy = process.env.HTTP_PROXY
const httpsProxy = process.env.HTTPS_PROXY
const noProxy = process.env.NO_PROXY

// Unset proxy environment variables
delete process.env.HTTP_PROXY
delete process.env.HTTPS_PROXY
delete process.env.NO_PROXY
                

runAction(options);