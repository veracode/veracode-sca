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


/**
 * Upload SCA scan artifacts
 * @param artifactClient - GitHub Actions artifact client
 * @param artifactName - Name of the artifact to create
 * @param files - Array of file paths to include in artifact
 */
async function uploadArtifacts(
    artifactClient: any,
    artifactName: string,
    files: string[]
): Promise<void> {
    const fileList = files.join(', ');
    core.info(`Uploading artifact '${artifactName}' with files: ${fileList}`);
    try {
        await artifactClient.uploadArtifact(artifactName, files, process.cwd(), { continueOnError: true });
        core.info(`✓ Successfully uploaded artifact with ${files.length} file(s)`);
    } catch (error: any) {
        core.warning(`Failed to upload artifact: ${error.message || error}`);
    }
}

/**
 * When using --show-cli flag, both JSON and CLI text are produced
 * This helper writes the CLI output (stdout) to scaResults.txt
 * @param cliOutput - The stdout from the scan command
 */
async function writeCliOutputToFile(cliOutput: string): Promise<void> {
    try {
        writeFileSync('scaResults.txt', cliOutput);
        core.info('CLI output written to scaResults.txt');
    } catch (error: any) {
        core.warning(`Failed to write CLI output to file: ${error.message || error}`);
    }
}

/**
 * Runs a unified scan with --show-cli flag when sca_fix_enabled
 * When sca_fix_enabled=true: Generates both JSON and CLI text output in one scan
 * When sca_fix_enabled=false: Generates output based on createIssues/jsonOutput flags
 * @param options - Scan options
 */
async function runScan(options: Options): Promise<void> {
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

        // Generate JSON when sca_fix_enabled (uses --show-cli for both JSON and CLI text in single scan)
        // or when createIssues is true (JSON for issue creation)
        const shouldGenerateJson = options.createIssues || options.scaFixEnabled;
        let commandOutput = '';

        if (options.scaFixEnabled) {
            // Use --json --show-cli for unified output (JSON to file, CLI text to stdout)
            commandOutput = `--json=${SCA_OUTPUT_FILE} --show-cli`;
        } else if (options.createIssues) {
            // JSON output for issue creation
            commandOutput = `--json=${SCA_OUTPUT_FILE}`;
        }

        // Always use the base artifact name regardless of output format
        // (whether it contains JSON+TXT with --show-cli or TXT only)
        const artifactNameBase = 'Veracode Agent Based SCA Results';
        extraCommands = `${extraCommands}${options.recursive ? '--recursive ' : ''}${options.quick ? '--quick ' : ''}${options.allowDirty ? '--allow-dirty ' : ''}${options.updateAdvisor ? '--update-advisor ' : ''}${skipVMS ? '--skip-vms ' : ''}${noGraphs ? '--no-graphs ' : ''}${options.debug ? '--debug ' : ''}${skipCollectorsAttr}${scanCollectorsAttr}`;

        if (runnerOS == 'Windows') {
            const powershellCommand = `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest https://sca-downloads.veracode.com/ci.ps1 -OutFile $env:TEMP\\ci.ps1; & $env:TEMP\\ci.ps1 -s -- scan ${extraCommands} ${commandOutput}"`

            if (shouldGenerateJson) {
                core.info('Starting the scan')
                let output: string = ''
                try {
                    output = execSync(powershellCommand, { encoding: 'utf-8', maxBuffer: 1024 * 1024 * 10 });//10MB
                    if (options.createIssues) {
                        core.info('Create issue "true" - on close')
                    }
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
                    if (error.status != null && error.status > 0 && (options.breakBuildOnPolicyFindings == 'true')) {
                        let summary_info = "Veracode SCA Scan failed with exit code " + error.statuscode + "\n"
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

                // PR decoration and issue generation (only if createIssues is enabled)
                if (options.createIssues) {
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
                }

                // Store output files as artifacts
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

                // When --show-cli is used, we also have CLI output that needs to be saved
                if (options.scaFixEnabled) {
                    // Write the CLI output (stdout) to scaResults.txt
                    await writeCliOutputToFile(output);
                    // Upload both JSON and TXT files
                    await uploadArtifacts(artifactClient, artifactNameBase, ['scaResults.json', 'scaResults.txt']);
                } else {
                    // JSON-only upload for create-issues
                    await uploadArtifacts(artifactClient, artifactNameBase, ['scaResults.json']);
                }

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
                        let summary_info = "Veracode SCA Scan failed with exit code " + error.statuscode + "\n"
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

                // Store output files as artifacts (skip if in dual-scan mode)
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

                await uploadArtifacts(artifactClient, artifactNameBase, ['scaResults.txt'])

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
                    commentBody += "<pre>Veracode SCA Scan finished" + "\n"
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

            if (shouldGenerateJson) {
                core.info('Starting the scan')
                await new Promise<void>((resolve, reject) => {
                    const execution = spawn('sh', ['-c', command], {
                        stdio: "pipe",
                        shell: false
                    });

                    execution.on('error', (data) => {
                        core.error(data);
                        reject(data);
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
                    if (options.createIssues) {
                        core.info('Create issue "true" - on close')
                    }
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

                    // PR decoration and issue generation (only if createIssues is enabled)
                    let summary_message = ""
                    if (options.createIssues) {
                        //Pull request decoration
                        core.info('check if we run on a pull request')
                        let pullRequest = process.env.GITHUB_REF
                        let isPR: any = pullRequest?.indexOf("pull")

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
                    }
                    // if scan was set to fail the pipeline should fail and show a summary of the scan results
                     if (code != null && code > 0 && (options.breakBuildOnPolicyFindings == 'true')) {
                        let summary_info = "Veracode SCA Scan failed with exit code " + code + "\n"
                        core.setFailed(summary_info)
                    }

                    // Store output files as artifacts
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

                    // When --show-cli is used, we also have CLI output that needs to be saved
                    if (options.scaFixEnabled) {
                        // Write the CLI output (stdout) to scaResults.txt
                        await writeCliOutputToFile(output);
                        // Upload both JSON and TXT files
                        await uploadArtifacts(artifactClient, artifactNameBase, ['scaResults.json', 'scaResults.txt']);
                    } else {
                        // Traditional JSON-only upload
                        await uploadArtifacts(artifactClient, artifactNameBase, ['scaResults.json']);
                    }

                    core.info('Finish command');
                    resolve();
                    });
                });


            } else {
                core.info('Command to run: ' + command)
                await new Promise<void>((resolve, reject) => {
                    const execution = spawn('sh', ['-c', command], {
                        stdio: "pipe",
                        shell: false
                    });

                    execution.on('error', (data) => {
                        core.error(data);
                        reject(data);
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

                    // Store output files as artifacts (skip if in dual-scan mode)
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

                    await uploadArtifacts(artifactClient, artifactNameBase, ['scaResults.txt'])

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
                        commentBody += "<pre>Veracode SCA Scan finished with exit code " + code + "\n"
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
                        let summary_info = "Veracode SCA Scan failed with exit code " + code + "\n"
                        core.setFailed(summary_info)
                    }
                    //run(options,core.info);
                    core.info('Finish command');
                    resolve();
                    });
                });
            }
        }

        // Generate vulnerability list after scan completes
        await generateVulnList(options);

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

/**
 * Main entry point - runs a single unified scan
 */
export async function runAction(options: Options) {
    try {
        // Single unified scan: when sca_fix_enabled, includes --show-cli for both JSON and CLI output
        await runScan(options);
    } catch (error) {
        if (error instanceof Error) {
            core.setFailed(error.message);
        } else {
            core.setFailed("Unknown error during scan execution");
        }
    }
}


/**
 * Generates SCA vulnerability list using Veracode CLI
 * This function is called at the end of runAction when sca_fix_enabled is true
 */
async function generateVulnList(options: Options): Promise<void> {
    try {
        core.info('=== Starting SCA Vulnerability List Generation ===');

        // Check if sca_fix_enabled is true
        if (!options.scaFixEnabled) {
            core.info('veracode-sca-fix is NOT enabled, skipping vulnerability list generation');
            return;
        }

        core.info('veracode-sca-fix is enabled, proceeding with vulnerability list generation');

        // Check if PR number exists in options
        if (!options.prNumber || options.prNumber === 0 || isNaN(options.prNumber)) {
            core.info('No PR number found in options, skipping vulnerability list generation');
            return;
        }

        const prNumber = options.prNumber;
        core.info(`PR number found: ${prNumber}`);

        // Check if scaResults.json exists
        if (!existsSync(SCA_OUTPUT_FILE)) {
            core.warning(`SCA results file not found: ${SCA_OUTPUT_FILE}. Skipping vulnerability list generation.`);
            return;
        }

        // Check for required environment variables
        const veracodeApiKeyId = process.env.VERACODE_API_KEY_ID;
        const veracodeApiKeySecret = process.env.VERACODE_API_KEY_SECRET;

        if (!veracodeApiKeyId || !veracodeApiKeySecret) {
            core.warning('VERACODE_API_KEY_ID or VERACODE_API_KEY_SECRET not set. Skipping vulnerability list generation.');
            return;
        }

        const workingDir = process.cwd();
        core.info(`Working directory: ${workingDir}`);

        // Check if helper/cli directory exists
        const helperCliPath = runnerOS === 'Windows'
            ? `${workingDir}\\veracode-helper\\helper\\cli`
            : `${workingDir}/veracode-helper/helper/cli`;

        if (!existsSync(helperCliPath)) {
            core.warning(`Helper CLI directory not found at ${helperCliPath}. Skipping vulnerability list generation.`);
            return;
        }

        let cliExecutablePath: string = '';
        let veracodeCommand: string;
        const vulnListingFile = 'veracode-cli.vuln.listing.json';

        if (runnerOS === 'Windows') {
            // Windows implementation
            // Find the CLI ps1 installer file
            const findPs1Command = `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '${helperCliPath}' -Filter *.ps1 | Select-Object -First 1 -ExpandProperty FullName"`;
            const installerFile = execSync(findPs1Command, { encoding: 'utf-8' }).trim();

            if (!installerFile || installerFile === '') {
                core.warning(`No CLI ps1 installer file found in ${helperCliPath}. Skipping vulnerability list generation.`);
                return;
            }

            core.info(`Found CLI installer: ${installerFile}`);

            // Run the installer to install Veracode CLI
            core.info('Running Veracode CLI installer...');
            try {
                const installCommand = `powershell -NoProfile -ExecutionPolicy Bypass -File "${installerFile}"`;
                const installOutput = execSync(installCommand, { encoding: 'utf-8' });
                core.info('Veracode CLI installation completed');
                if (core.isDebug()) {
                    core.info(installOutput);
                }
            } catch (error: any) {
                core.warning(`Failed to install Veracode CLI: ${error.message}`);
                return;
            }

            // Check where veracode command is located using Get-Command
            core.info('Set veracode.exe command location...');
            const appDataPath = process.env.APPDATA || '';
            if (!appDataPath) {
                core.warning('APPDATA environment variable not found. Skipping vulnerability list generation.');
                return;
            }
            cliExecutablePath = `${appDataPath}\\veracode\\veracode.exe`;
            core.info(`Expected Veracode CLI installation path: ${cliExecutablePath}`);

            // Verify the CLI was installed
            if (!existsSync(cliExecutablePath)) {
                core.warning(`Veracode CLI not found at ${cliExecutablePath}. Installation may have failed.`);
                return;
            }

            core.info(`Veracode CLI successfully installed and verified at: ${cliExecutablePath}`);

            // Build the veracode fix sca command for Windows using full path
            veracodeCommand = `"${cliExecutablePath}" fix sca "${workingDir}" -r "${workingDir}\\${SCA_OUTPUT_FILE}" --list-only --transitive --json "${vulnListingFile}"`;

            core.info(`Running command: ${veracodeCommand}`);

        } else {
            // Linux/Unix implementation
            // Find the CLI tar.gz file
            const cliFiles = execSync(`ls -1 ${helperCliPath}/*.tar.gz 2>/dev/null || echo ""`, { encoding: 'utf-8' }).trim();
            if (!cliFiles) {
                core.warning(`No CLI tar.gz file found in ${helperCliPath}. Skipping vulnerability list generation.`);
                return;
            }

            const cliFile = cliFiles.split('\n')[0]; // Get first file
            const cliFileName = cliFile.replace('.tar.gz', '').split('/').pop();

            core.info(`Found CLI file: ${cliFile}`);
            core.info(`Extracting to: ${cliFileName}`);

            // Extract the CLI
            execSync(`cd ${helperCliPath} && tar -zxf ${cliFile.split('/').pop()}`, { encoding: 'utf-8' });

            cliExecutablePath = `${helperCliPath}/${cliFileName}`;
            core.info(`CLI executable path: ${cliExecutablePath}`);

            // Build the veracode fix sca command
            veracodeCommand = `${cliExecutablePath}/veracode fix sca "${workingDir}" -r "${workingDir}/${SCA_OUTPUT_FILE}" --list-only --transitive --json "${vulnListingFile}"`;

            core.info(`Running command: ${veracodeCommand}`);
        }

        // Run the veracode fix sca command
        try {
            const output = execSync(veracodeCommand, {
                encoding: 'utf-8',
                env: {
                    ...process.env,
                    VERACODE_API_KEY_ID: veracodeApiKeyId,
                    VERACODE_API_KEY_SECRET: veracodeApiKeySecret
                }
            });

            core.info('Veracode CLI execution successful');
            if (core.isDebug()) {
                core.info(output);
            }

            // Check if vulnerability listing file was created
            if (!existsSync(vulnListingFile)) {
                core.warning(`Vulnerability listing file not created: ${vulnListingFile}`);
                return;
            }

            // Upload the vulnerability listing JSON as artifact
            core.info('Uploading SCA vulnerability listing JSON as artifact');
            const { DefaultArtifactClient } = require('@actions/artifact');
            const artifactV1 = require('@actions/artifact-v1');
            let artifactClient;

            if (options?.platformType === 'ENTERPRISE') {
                artifactClient = artifactV1.create();
                core.info('Initialized artifact client using version V1');
            } else {
                artifactClient = new DefaultArtifactClient();
                core.info('Initialized artifact client using version V2');
            }

            const artifactName = 'sca-vuln-listing-json';
            const files = [vulnListingFile];
            const rootDirectory = workingDir;
            const artifactOptions = {
                continueOnError: true
            };

            await artifactClient.uploadArtifact(artifactName, files, rootDirectory, artifactOptions);
            core.info('Successfully uploaded vulnerability listing JSON');

            core.info('=== SCA Vulnerability List Generation Complete ===');

        } catch (error: any) {
            core.error('Failed to run Veracode CLI command');
            core.error(error.message || error);
            if (error.stdout) {
                core.error(`stdout: ${error.stdout}`);
            }
            if (error.stderr) {
                core.error(`stderr: ${error.stderr}`);
            }
            // Don't fail the entire action, just log the error
            core.warning('Vulnerability list generation failed, but continuing action execution');
        }
    } catch (error: any) {
            core.error('Error during vulnerability list generation');
            core.error(error.message || error);
            core.warning('Vulnerability list generation failed, but continuing action execution');
            // Don't fail the action if vulnerability list generation fails
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

