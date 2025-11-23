import {runAction} from '../srcclr';
import { Options } from "../options";
import * as dotenv from 'dotenv';
dotenv.config();

const options: Options = {
    quick: false,
    updateAdvisor: false,
    minCVSSForIssue: 11,
    url: 'https://www.github.com/dancancro/great-big-example-application',
    github_token: process.env.GITHUB_TOKEN || '',
    createIssues: false,
    failOnCVSS: 10,
    path: '.',
    debug:false,
    "skip-collectors": [],
    allowDirty: false,
    recursive:false,
    "skip-vms":false,
    "no-graphs":false,
    platformType:'CLOUD',
    breakBuildOnPolicyFindings:'false',
    dependabot_alerts: false
}

runAction(options);


