#!/usr/bin/env node
import { execSync, spawn } from "child_process";

import * as core from '@actions/core'
import { Options } from "./options";
import { SCA_OUTPUT_FILE, run, runText } from "./index";
import * as github from '@actions/github'
import { env } from "process";
import { writeFile } from 'fs';
import { readFileSync, existsSync } from 'fs';
import { writeFileSync } from 'fs';

const runnerOS = process.env.RUNNER_OS;
const cleanCollectors = (inputArr: Array<string>) => {
    let allowed: Array<string> = [];
    for (var input of inputArr) {
        if (input && collectors.indexOf(input.trim().toLowerCase()) > -1) {
            allowed.push(input.trim().toLowerCase());
        }
    }
    return allowed;
}

/**
 * Extracts the scan URL from the Veracode SCA output
 * Looks for a line containing "Full Report Details" followed by a URL
 * Also tries to extract from JSON metadata if available
 */
const extractScanUrl = (output: string): string | null => {
    core.info('=== Starting URL extraction ===');
    
    if (!output) {
        core.info('extractScanUrl: output is empty or null');
        return null;
    }
    
    core.info(`extractScanUrl: Output length is ${output.length} characters`);
    
    // Pattern to match: "Full Report Details" followed by whitespace and a URL
    // More flexible pattern that handles various whitespace amounts
    // Matches: "Full Report Details" followed by any whitespace and then a URL starting with http:// or https://
    const patterns = [
        /Full\s+Report\s+Details\s+(https?:\/\/[^\s\r\n]+)/i,  // Explicit URL pattern - most common
        /Full\s+Report\s+Details[:\s]+(https?:\/\/[^\s\r\n]+)/i,  // With optional colon
        /Full\s+Report\s+Details\s+(\S+)/i,  // Fallback to any non-whitespace
        /Full\s+Report\s+Details[:\s]+(https?:\/\/[^\r\n]+)/i,  // Handle newlines
    ];
    
    // First, check if "Full Report Details" appears in the output at all
    const hasFullReport = /Full\s+Report\s+Details/i.test(output);
    core.info(`extractScanUrl: "Full Report Details" found in output: ${hasFullReport}`);
    
    if (hasFullReport) {
        // Find the line containing "Full Report Details"
        const lines = output.split('\n');
        const fullReportLine = lines.find(line => /Full\s+Report\s+Details/i.test(line));
        if (fullReportLine) {
            core.info(`extractScanUrl: Found line: "${fullReportLine.trim()}"`);
        }
    }
    
    for (let i = 0; i < patterns.length; i++) {
        const pattern = patterns[i];
        const match = output.match(pattern);
        if (match && match[1]) {
            const url = match[1].trim();
            // Validate it's a URL
            if (url.startsWith('http://') || url.startsWith('https://')) {
                core.info(`extractScanUrl: ✓ Found URL using pattern ${i + 1}: ${url}`);
                return url;
            } else {
                core.info(`extractScanUrl: Pattern ${i + 1} matched but result is not a URL: ${url}`);
            }
        }
    }
    
    core.info('extractScanUrl: No URL found in text output, trying JSON fallback');
    
    // Fallback: Try to extract from JSON if available
    try {
        if (existsSync(SCA_OUTPUT_FILE)) {
            core.info(`extractScanUrl: JSON file exists, attempting to read: ${SCA_OUTPUT_FILE}`);
            const scaResultsTxt = readFileSync(SCA_OUTPUT_FILE);
            const scaResJson = JSON.parse(scaResultsTxt.toString('utf-8'));
            if (scaResJson.records && scaResJson.records[0] && scaResJson.records[0].metadata && scaResJson.records[0].metadata.report) {
                const url = scaResJson.records[0].metadata.report;
                if (url.startsWith('http://') || url.startsWith('https://')) {
                    core.info(`extractScanUrl: ✓ Found URL in JSON metadata: ${url}`);
                    return url;
                }
            } else {
                core.info('extractScanUrl: JSON file exists but does not contain report URL in expected structure');
            }
        } else {
            core.info(`extractScanUrl: JSON file does not exist: ${SCA_OUTPUT_FILE}`);
        }
    } catch (error: any) {
        core.info(`extractScanUrl: Error reading JSON fallback: ${error.message || error}`);
    }
    
    core.info('extractScanUrl: ✗ No URL found in output or JSON');
    core.info('=== URL extraction complete ===');
    
    return null;
}

export async function runAction(options: Options) {
    try {

        core.info('Start command');
        let extraCommands: string = '';
        if (options.url.length > 0) {
            extraCommands = `--url ${options.url} `;
        } else {
            extraCommands = `${options.path} `;
        }

        const skip = cleanCollectors(options["skip-collectors"]);
        let skipCollectorsAttr = '';
        if (skip.length > 0) {
            skipCollectorsAttr = `--skip-collectors ${skip.toString()} `;
        }

        const scan = cleanCollectors(options["scan-collectors"]);
        let scanCollectorsAttr = '';
        if (scan.length > 0) {
            scanCollectorsAttr = `--scan-collectors ${scan.toString()} `;
        }

        const noGraphs = options["no-graphs"]
        const skipVMS = options["skip-vms"]

        const commandOutput = options.createIssues ? `--json=${SCA_OUTPUT_FILE}` : '';
        extraCommands = `${extraCommands}${options.recursive ? '--recursive ' : ''}${options.quick ? '--quick ' : ''}${options.allowDirty ? '--allow-dirty ' : ''}${options.updateAdvisor ? '--update-advisor ' : ''}${skipVMS ? '--skip-vms ' : ''}${noGraphs ? '--no-graphs ' : ''}${options.debug ? '--debug ' : ''}${skipCollectorsAttr}${scanCollectorsAttr}`;

        if (runnerOS == 'Windows') {
            const powershellCommand = `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest https://sca-downloads.veracode.com/ci.ps1 -OutFile $env:TEMP\\ci.ps1; & $env:TEMP\\ci.ps1 -s -- scan ${extraCommands} ${commandOutput}; exit $LASTEXITCODE"`
            if (options.createIssues) {
                core.info('Starting the scan')
                let output: string = ''
                try {
                    output = execSync(powershellCommand, { encoding: 'utf-8', maxBuffer: 1024 * 1024 * 10 });//10MB
                    core.info('Create issue "true" - on close')
                    if (core.isDebug()) {
                        core.info(output);
                    }
                    
                    // Extract and set scan URL output
                    const scanUrl = extractScanUrl(output);
                    if (scanUrl) {
                        core.setOutput('scan-url', scanUrl);
                        core.info(`Scan URL extracted: ${scanUrl}`);
                    } else {
                        core.info('Scan URL not found in output');
                    }
                }
                catch (error: any) {
                    console.log((error.stdout).toString())
                    if (error.status != null && error.status > 0 && (options.breakBuildOnPolicyFindings == 'true')) {
                        let summary_info = "Veraocde SCA Scan failed with exit code " + error.status + "\n"
                        core.info(output)
                        core.setFailed(summary_info)
                    }
                    
                    // Try to extract URL even if there was an error
                    const scanUrl = extractScanUrl(output);
                    if (scanUrl) {
                        core.setOutput('scan-url', scanUrl);
                        core.info(`Scan URL extracted: ${scanUrl}`);
                    }
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
                    summary_message = `Veracode SCA Scan finished. Please review created and linked issues`

                    try {
                        const baseUrl = process.env.GITHUB_API_URL || 'https://api.github.com';
                        const octokit = github.getOctokit(options.github_token, { baseUrl });

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
                    summary_message = `Veracode SCA Scan finished. Please review created issues`
                }

                //Generate issues
                run(options, core.info);

                core.info(summary_message);

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
            } else {
                core.info('Command to run: ' + powershellCommand)
                let output: string = ''
                let stderrOutput: string = ''
                try {
                    // execSync captures both stdout and stderr by default, but let's be explicit
                    output = execSync(powershellCommand, { 
                        encoding: 'utf-8', 
                        maxBuffer: 1024 * 1024 * 10,
                        stdio: ['pipe', 'pipe', 'pipe'] // stdin, stdout, stderr
                    });//10MB
                    core.info(output);
                    
                    core.info(`Attempting to extract scan URL from output (length: ${output.length} chars)`);
                    
                    // Extract and set scan URL output
                    const scanUrl = extractScanUrl(output);
                    if (scanUrl) {
                        core.setOutput('scan-url', scanUrl);
                        core.info(`✓✓✓ SUCCESS: Scan URL extracted and set as output: ${scanUrl}`);
                    } else {
                        core.warning('✗✗✗ FAILED: Scan URL not found in output');
                        // Try to find the line with "Full Report Details" for debugging
                        const lines = output.split('\n');
                        const fullReportLine = lines.find(line => line.toLowerCase().includes('full report details'));
                        if (fullReportLine) {
                            core.info(`Found "Full Report Details" line: ${fullReportLine}`);
                        } else {
                            core.info('"Full Report Details" line not found in output');
                        }
                    }
                }
                catch (error: any) {
                    // execSync throws on non-zero exit, but output might still be in error.stdout or error.stderr
                    if (error.stdout) {
                        output = error.stdout.toString();
                    }
                    if (error.stderr) {
                        stderrOutput = error.stderr.toString();
                    }
                    
                    if (error.status != null && error.status > 0 && (options.breakBuildOnPolicyFindings == 'true')) {
                        let summary_info = "Veraocde SCA Scan failed with exit code " + error.status + "\n"
                        core.setFailed(summary_info)
                    }
                    
                    // Try to extract URL from combined output even if there was an error
                    const combinedOutput = `${output}${stderrOutput}`;
                    const scanUrl = extractScanUrl(combinedOutput);
                    if (scanUrl) {
                        core.setOutput('scan-url', scanUrl);
                        core.info(`Scan URL extracted from error output: ${scanUrl}`);
                    } else if (core.isDebug()) {
                        core.info(`Could not extract URL. Output length: ${output.length}, stderr length: ${stderrOutput.length}`);
                    }
                }

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
                    commentBody += "<pre>Veraocde SCA Scan finished" + "\n"
                    commentBody += '\n<details><summary>Veracode SCA Scan details</summary><p>\n'
                    commentBody += output //.replace(/    /g, '&nbsp;&nbsp;&nbsp;&nbsp;');
                    commentBody += '</p></details>\n</pre>'




                    try {
                        const baseUrl = process.env.GITHUB_API_URL || 'https://api.github.com';
                        const octokit = github.getOctokit(options.github_token, { baseUrl });

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

                //run(options,core.info);
                core.info('Finish command');
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
                let stderrOutput: string = '';
                execution.stdout!.on('data', (data) => {
                    output = `${output}${data}`;
                });

                execution.stderr!.on('data', (data) => {
                    const dataStr = data.toString();
                    stderrOutput = `${stderrOutput}${dataStr}`;
                    core.error(`stderr: ${dataStr}`);
                });

                execution.on('close', async (code) => {
                    core.info('Create issue "true" - on close')
                    if (core.isDebug()) {
                        core.info(output);
                    }

                    // Combine stdout and stderr for URL extraction (URL might be in either)
                    const combinedOutput = `${output}${stderrOutput}`;
                    core.info(`Attempting to extract scan URL from combined output (stdout: ${output.length} chars, stderr: ${stderrOutput.length} chars)`);

                    // Extract and set scan URL output from combined output
                    const scanUrl = extractScanUrl(combinedOutput);
                    if (scanUrl) {
                        core.setOutput('scan-url', scanUrl);
                        core.info(`✓✓✓ SUCCESS: Scan URL extracted and set as output: ${scanUrl}`);
                    } else {
                        core.warning('✗✗✗ FAILED: Scan URL not found in output');
                        core.info(`Output length: ${output.length}, stderr length: ${stderrOutput.length}, combined: ${combinedOutput.length}`);
                        // Log a sample of the output to help debug
                        const fullReportIndex = combinedOutput.indexOf('Full Report');
                        if (fullReportIndex >= 0) {
                            const sampleOutput = combinedOutput.substring(Math.max(0, fullReportIndex - 50), Math.min(combinedOutput.length, fullReportIndex + 200));
                            core.info(`Sample output around "Full Report" (index ${fullReportIndex}): ${sampleOutput}`);
                        } else {
                            core.info('"Full Report" text not found in combined output');
                        }
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
                            const baseUrl = process.env.GITHUB_API_URL || 'https://api.github.com';
                            const octokit = github.getOctokit(options.github_token, { baseUrl });

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
                let stderrOutput: string = '';
                execution.stdout!.on('data', (data) => {
                    const dataStr = data.toString();
                    output = `${output}${dataStr}`;
                    // Also log to see output in real-time
                    core.info(dataStr);
                });

                execution.stderr!.on('data', (data) => {
                    const dataStr = data.toString();
                    stderrOutput = `${stderrOutput}${dataStr}`;
                    core.error(`stderr: ${dataStr}`);
                });

                execution.on('close', async (code) => {
                    //core.info(output);
                    core.info(`Scan finished with exit code:  ${code}`);

                    // Combine stdout and stderr for URL extraction (URL might be in either)
                    const combinedOutput = `${output}${stderrOutput}`;
                    core.info(`Attempting to extract scan URL from combined output (stdout: ${output.length} chars, stderr: ${stderrOutput.length} chars)`);
                    
                    // Extract and set scan URL output from combined output
                    const scanUrl = extractScanUrl(combinedOutput);
                    if (scanUrl) {
                        core.setOutput('scan-url', scanUrl);
                        core.info(`✓✓✓ SUCCESS: Scan URL extracted and set as output: ${scanUrl}`);
                    } else {
                        core.warning('✗✗✗ FAILED: Scan URL not found in output');
                        core.info(`Output length: ${output.length}, stderr length: ${stderrOutput.length}, combined: ${combinedOutput.length}`);
                        // Log a sample of the output to help debug
                        const fullReportIndex = combinedOutput.indexOf('Full Report');
                        if (fullReportIndex >= 0) {
                            const sampleOutput = combinedOutput.substring(Math.max(0, fullReportIndex - 50), Math.min(combinedOutput.length, fullReportIndex + 200));
                            core.info(`Sample output around "Full Report" (index ${fullReportIndex}): ${sampleOutput}`);
                        } else {
                            core.info('"Full Report" text not found in combined output');
                        }
                    }
                    //write output to file
                    // writeFile('scaResults.txt', output, (err) => {
                    //     if (err) throw err;
                    //     console.log('The file has been saved!');
                    // });

                    try {
                        writeFileSync('scaResults.txt', combinedOutput);
                        console.log('The file has been saved!');
                    } catch (err) {
                        console.error('Error writing file:', err);
                    }

                    // Try to extract URL from the file as well (in case output variable missed something)
                    let fileOutput = combinedOutput;
                    try {
                        if (existsSync('scaResults.txt')) {
                            const fileContent = readFileSync('scaResults.txt', 'utf8');
                            if (fileContent && fileContent.length > combinedOutput.length) {
                                fileOutput = fileContent;
                                if (core.isDebug()) {
                                    core.info('Using file content for URL extraction (file is larger than captured output)');
                                }
                            }
                        }
                    } catch (err) {
                        // Ignore file read errors
                    }

                    // Re-extract URL from file output if not found in combined output
                    if (!scanUrl) {
                        const scanUrlFromFile = extractScanUrl(fileOutput);
                        if (scanUrlFromFile) {
                            core.setOutput('scan-url', scanUrlFromFile);
                            core.info(`Scan URL extracted from file: ${scanUrlFromFile}`);
                        }
                    }

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
                            const baseUrl = process.env.GITHUB_API_URL || 'https://api.github.com';
                            const octokit = github.getOctokit(options.github_token, { baseUrl });

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
    "maven",
    "gradle",
    "ant",
    "jar",
    "sbt",
    "glide",
    "go get",
    "go mod",
    "godep",
    "dep",
    "govendor",
    "trash",
    "pip",
    "pipenv",
    "bower",
    "yarn",
    "npm",
    "cocoapods",
    "gem",
    "composer",
    "makefile",
    "dll",
    "msbuilddotnet",
]

