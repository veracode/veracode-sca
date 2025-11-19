#!/usr/bin/env node
import { execSync, spawn } from "child_process";

import * as core from '@actions/core'
import { Options } from "./options";
import { SCA_OUTPUT_FILE,run, runText } from "./index";
import * as github from '@actions/github'
import { env } from "process";
import { writeFile } from 'fs';
import { readFileSync } from 'fs';
import { writeFileSync } from 'fs';

const runnerOS = process.env.RUNNER_OS;
const cleanCollectors = (inputArr:Array<string>) => {
    let allowed:Array<string> = [];
    for (var input of inputArr) {
        if (input && collectors.indexOf(input.trim().toLowerCase())>-1) {
            allowed.push(input.trim().toLowerCase());
        }
    }
    return allowed;
}

export async function runAction (options: Options)  {
    try {
  
        core.info('Start command');
        let extraCommands: string = '';
        if (options.url.length>0) {
            extraCommands = `--url ${options.url} `;
        } else {
            extraCommands = `${options.path} `;
        }

        const skip = cleanCollectors(options["skip-collectors"]);
        let skipCollectorsAttr = '';
        if (skip.length>0) {
            skipCollectorsAttr = `--skip-collectors ${skip.toString()} `;
        }

        const noGraphs = options["no-graphs"]
        const skipVMS = options["skip-vms"]

        const commandOutput = options.createIssues ? `--json=${SCA_OUTPUT_FILE}` : '';
        extraCommands = `${extraCommands}${options.recursive ? '--recursive ' : ''}${options.quick ? '--quick ' : ''}${options.allowDirty ? '--allow-dirty ' : ''}${options.updateAdvisor ? '--update-advisor ' : ''}${skipVMS ? '--skip-vms ' : ''}${noGraphs ? '--no-graphs ' : ''}${options.debug ? '--debug ' : ''}${skipCollectorsAttr}`;
        if (runnerOS == 'Windows') {
            const powershellCommand = `"Invoke-WebRequest https://sca-downloads.veracode.com/ci.ps1 -OutFile $env:TEMP\\ci.ps1; & $env:TEMP\\ci.ps1 -s -- scan ${extraCommands} ${commandOutput}"`
            if (options.createIssues) {
                core.info('Starting the scan')

                const execution = spawn('powershell.exe', [
                    "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershellCommand], {
                    stdio: "pipe"
                });

                execution.on('error', (data) => {
                    core.error(data);
                })

                let output: string = '';
                execution.stdout.on('data', (data) => {
                    output = `${output}${data}`;
                });

                execution.on('close', async (code) => {
                    core.info('Create issue "true" - on close')
                    if (core.isDebug()) {
                        core.info(output);
                    }

                    //Pull request decoration
                    core.info('check if we run on a pull request')
                    let pullRequest = process.env.GITHUB_REF
                    let isPR: any = pullRequest?.indexOf("pull")
                    let summary_message = ""

                    if (isPR >= 1) {
                        core.info('We run on a PR, add more messaging')
                        const context = github.context
                        const repository: any = process.env.GITHUB_REPOSITORY
                        const repo = repository.split("/");
                        const commentID: any = context.payload.pull_request?.number
                        let pr_header = '<br>![](https://www.veracode.com/themes/veracode_new/library/img/veracode-black-hires.svg)<br>'
                        summary_message = `Veracode SCA Scan finished with exit code: ${code}. Please review created and linked issues`

                        try {
                            const octokit = github.getOctokit(options.github_token);

                            const { data: comment } = await octokit.rest.issues.createComment({
                                owner: repo[0],
                                repo: repo[1],
                                issue_number: commentID,
                                body: pr_header + summary_message,
                            });
                            core.info('Adding scan results message as comment to PR #' + commentID)
                        } catch (error: any) {
                            core.info(error);
                        }
                    }
                    else {
                        summary_message = `Veracode SCA Scan finished with exit code: ${code}. Please review created issues`
                    }

                    //Generate issues
                    run(options, core.info);

                    core.info(summary_message);
                    // if scan was set to fail the pipeline should fail and show a summary of the scan results
                    if (code != null && code > 0) {
                        core.setFailed(summary_message)
                    }

                    //store output files as artifacts
                    core.info('Store json Results as Artifact')
                    const { DefaultArtifactClient } = require('@actions/artifact');
                    const artifactV1 = require('@actions/artifact-v1');
                    let artifactClient;

                    if (options?.platformType === 'ENTERPRISE') {
                        artifactClient = artifactV1.create();
                        core.info(`Initialized the artifact object using version V1.`);
                    } else {
                        artifactClient = new DefaultArtifactClient();
                        core.info(`Initialized the artifact object using version V2.`);
                    }
                    const artifactName = 'Veracode Agent Based SCA Results';
                    const files = [
                        'scaResults.json'
                    ]

                    const rootDirectory = process.cwd()
                    const artefactOptions = {
                        continueOnError: true
                    }

                    const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, artefactOptions)


                    core.info('Finish command');
                });


            } else {
                core.info('Command to run: ' + powershellCommand)
                const execution = spawn('powershell', [
                    "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershellCommand], {
                    stdio: "pipe",
                    shell: false
                });

                execution.on('error', (data) => {
                    core.error(data);
                })

                let output: string = '';
                execution.stdout!.on('data', (data) => {
                    output = `${output}${data}`;
                });

                execution.stderr!.on('data', (data) => {
                    core.error(`stderr: ${data}`);
                });

                execution.on('close', async (code) => {
                    //core.info(output);
                    core.info(`Scan finished with exit code:  ${code}`);

                    core.info(output)
                    //write output to file
                    // writeFile('scaResults.txt', output, (err) => {
                    //     if (err) throw err;
                    //     console.log('The file has been saved!');
                    // });

                    try {
                        writeFileSync('scaResults.txt', output);
                        console.log('The file has been saved!');
                    } catch (err) {
                        console.error('Error writing file:', err);
                    }


                    // core.info('reading file')
                    // try {
                    //     const data = readFileSync('scaResults.txt', 'utf8');
                    //     console.log('Full file output: '+data);
                    // } catch (err) {
                    //     console.error(err);
                    // }

                    //store output files as artifacts
                    core.info('Store txt Results as Artifact')
                    const { DefaultArtifactClient } = require('@actions/artifact');
                    const artifactV1 = require('@actions/artifact-v1');
                    let artifactClient;

                    if (options?.platformType === 'ENTERPRISE') {
                        artifactClient = artifactV1.create();
                        core.info(`Initialized the artifact object using version V1.`);
                    } else {
                        artifactClient = new DefaultArtifactClient();
                        core.info(`Initialized the artifact object using version V2.`);
                    }
                    const artifactName = 'Veracode Agent Based SCA Results';
                    const files = [
                        'scaResults.txt'
                    ]

                    const rootDirectory = process.cwd()
                    const artefactOptions = {
                        continueOnError: true
                    }

                    const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, artefactOptions)






                    //Pull request decoration
                    core.info('check if we run on a pull request')
                    let pullRequest = process.env.GITHUB_REF
                    let isPR: any = pullRequest?.indexOf("pull")

                    if (isPR >= 1) {
                        core.info("This run is part of a PR, should add some PR comment")

                        const context = github.context
                        const repository: any = process.env.GITHUB_REPOSITORY
                        const repo = repository.split("/");
                        const commentID: any = context.payload.pull_request?.number


                        let commentBody = '<br>![](https://www.veracode.com/sites/default/files/2022-04/logo_1.svg)<br>'
                        commentBody += "<pre>Veraocde SCA Scan finished with exit code " + code + "\n"
                        commentBody += '\n<details><summary>Veracode SCA Scan details</summary><p>\n'
                        commentBody += output //.replace(/    /g, '&nbsp;&nbsp;&nbsp;&nbsp;');
                        commentBody += '</p></details>\n</pre>'




                        try {
                            const octokit = github.getOctokit(options.github_token);

                            const { data: comment } = await octokit.rest.issues.createComment({
                                owner: repo[0],
                                repo: repo[1],
                                issue_number: commentID,
                                body: commentBody,
                            });
                            core.info('Adding scan results as comment to PR #' + commentID)
                        } catch (error: any) {
                            core.info(error);
                        }

                    }




                    // if scan was set to fail the pipeline should fail and show a summary of the scan results
                    if (code != null && code > 0 && (options.breakBuildOnPolicyFindings == 'true')) {
                        let summary_info = "Veraocde SCA Scan failed with exit code " + code + "\n"
                        core.setFailed(summary_info)
                    }
                    //run(options,core.info);
                    core.info('Finish command');
                });
            }
        }
        else {
            const command = `curl -sSL https://download.sourceclear.com/ci.sh | sh -s -- scan ${extraCommands} ${commandOutput}`;
            core.info(command);

            if (options.createIssues) {
                core.info('Starting the scan')
                const execution = spawn('sh', ['-c', command], {
                    stdio: "pipe",
                    shell: false
                });

                execution.on('error', (data) => {
                    core.error(data);
                })

                let output: string = '';
                execution.stdout!.on('data', (data) => {
                    output = `${output}${data}`;
                });

                execution.stderr!.on('data', (data) => {
                    core.error(`stderr: ${data}`);
                });

                execution.on('close', async (code) => {
                    core.info('Create issue "true" - on close')
                    if (core.isDebug()) {
                        core.info(output);
                    }

                    //Pull request decoration
                    core.info('check if we run on a pull request')
                    let pullRequest = process.env.GITHUB_REF
                    let isPR: any = pullRequest?.indexOf("pull")
                    let summary_message = ""

                    if (isPR >= 1) {
                        core.info('We run on a PR, add more messaging')
                        const context = github.context
                        const repository: any = process.env.GITHUB_REPOSITORY
                        const repo = repository.split("/");
                        const commentID: any = context.payload.pull_request?.number
                        let pr_header = '<br>![](https://www.veracode.com/themes/veracode_new/library/img/veracode-black-hires.svg)<br>'
                        summary_message = `Veracode SCA Scan finished with exit code: ${code}. Please review created and linked issues`

                        try {
                            const octokit = github.getOctokit(options.github_token);

                            const { data: comment } = await octokit.rest.issues.createComment({
                                owner: repo[0],
                                repo: repo[1],
                                issue_number: commentID,
                                body: pr_header + summary_message,
                            });
                            core.info('Adding scan results message as comment to PR #' + commentID)
                        } catch (error: any) {
                            core.info(error);
                        }
                    }
                    else {
                        summary_message = `Veracode SCA Scan finished with exit code: ${code}. Please review created issues`
                    }

                    //Generate issues
                    run(options, core.info);

                    core.info(summary_message);
                    // if scan was set to fail the pipeline should fail and show a summary of the scan results
                    if (code != null && code > 0) {
                        core.setFailed(summary_message)
                    }

                    //store output files as artifacts
                    core.info('Store json Results as Artifact')
                    const { DefaultArtifactClient } = require('@actions/artifact');
                    const artifactV1 = require('@actions/artifact-v1');
                    let artifactClient;

                    if (options?.platformType === 'ENTERPRISE') {
                        artifactClient = artifactV1.create();
                        core.info(`Initialized the artifact object using version V1.`);
                    } else {
                        artifactClient = new DefaultArtifactClient();
                        core.info(`Initialized the artifact object using version V2.`);
                    }
                    const artifactName = 'Veracode Agent Based SCA Results';
                    const files = [
                        'scaResults.json'
                    ]

                    const rootDirectory = process.cwd()
                    const artefactOptions = {
                        continueOnError: true
                    }

                    const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, artefactOptions)




                    core.info('Finish command');
                });


            } else {
                core.info('Command to run: ' + command)
                const execution = spawn('sh', ['-c', command], {
                    stdio: "pipe",
                    shell: false
                });

                execution.on('error', (data) => {
                    core.error(data);
                })

                let output: string = '';
                execution.stdout!.on('data', (data) => {
                    output = `${output}${data}`;
                });

                execution.stderr!.on('data', (data) => {
                    core.error(`stderr: ${data}`);
                });

                execution.on('close', async (code) => {
                    //core.info(output);
                    core.info(`Scan finished with exit code:  ${code}`);

                    core.info(output)
                    //write output to file
                    // writeFile('scaResults.txt', output, (err) => {
                    //     if (err) throw err;
                    //     console.log('The file has been saved!');
                    // });

                    try {
                        writeFileSync('scaResults.txt', output);
                        console.log('The file has been saved!');
                    } catch (err) {
                        console.error('Error writing file:', err);
                    }


                    // core.info('reading file')
                    // try {
                    //     const data = readFileSync('scaResults.txt', 'utf8');
                    //     console.log('Full file output: '+data);
                    // } catch (err) {
                    //     console.error(err);
                    // }

                    //store output files as artifacts
                    core.info('Store txt Results as Artifact')
                    const { DefaultArtifactClient } = require('@actions/artifact');
                    const artifactV1 = require('@actions/artifact-v1');
                    let artifactClient;

                    if (options?.platformType === 'ENTERPRISE') {
                        artifactClient = artifactV1.create();
                        core.info(`Initialized the artifact object using version V1.`);
                    } else {
                        artifactClient = new DefaultArtifactClient();
                        core.info(`Initialized the artifact object using version V2.`);
                    }
                    const artifactName = 'Veracode Agent Based SCA Results';
                    const files = [
                        'scaResults.txt'
                    ]

                    const rootDirectory = process.cwd()
                    const artefactOptions = {
                        continueOnError: true
                    }

                    const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, artefactOptions)






                    //Pull request decoration
                    core.info('check if we run on a pull request')
                    let pullRequest = process.env.GITHUB_REF
                    let isPR: any = pullRequest?.indexOf("pull")

                    if (isPR >= 1) {
                        core.info("This run is part of a PR, should add some PR comment")

                        const context = github.context
                        const repository: any = process.env.GITHUB_REPOSITORY
                        const repo = repository.split("/");
                        const commentID: any = context.payload.pull_request?.number


                        let commentBody = '<br>![](https://www.veracode.com/sites/default/files/2022-04/logo_1.svg)<br>'
                        commentBody += "<pre>Veraocde SCA Scan finished with exit code " + code + "\n"
                        commentBody += '\n<details><summary>Veracode SCA Scan details</summary><p>\n'
                        commentBody += output //.replace(/    /g, '&nbsp;&nbsp;&nbsp;&nbsp;');
                        commentBody += '</p></details>\n</pre>'




                        try {
                            const octokit = github.getOctokit(options.github_token);

                            const { data: comment } = await octokit.rest.issues.createComment({
                                owner: repo[0],
                                repo: repo[1],
                                issue_number: commentID,
                                body: commentBody,
                            });
                            core.info('Adding scan results as comment to PR #' + commentID)
                        } catch (error: any) {
                            core.info(error);
                        }

                    }




                    // if scan was set to fail the pipeline should fail and show a summary of the scan results
                    if (code != null && code > 0 && (options.breakBuildOnPolicyFindings == 'true')) {
                        let summary_info = "Veraocde SCA Scan failed with exit code " + code + "\n"
                        core.setFailed(summary_info)
                    }
                    //run(options,core.info);
                    core.info('Finish command');
                });
            }
        }

    } catch (error) {
        if (error instanceof Error) {
            core.info('Running scan failed.')
            //const output = stdout.toString();
            core.info(error.message);
            //core.setFailed(error.message);
        } else {
            core.setFailed("unknown error");
            console.log(error);
        }
    }
}


const collectors = [
    "maven"	,
"gradle",
"ant",
"jar",
"sbt",	
"glide"	,
"go get",
"go mod",
"godep",
"dep",
"govendor",
"trash",
"pip"	,
"pipenv",
"bower"	,
"yarn",
"npm",
"cocoapods",	
"gem",
"composer"	,
"makefile"	,
"dll",
"msbuilddotnet",
]

