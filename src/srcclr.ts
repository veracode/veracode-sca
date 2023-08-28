#!/usr/bin/env node
import { execSync, spawn } from "child_process";

import * as core from '@actions/core'
import { Options } from "./options";
import { SCA_OUTPUT_FILE,run, runText } from "./index";
import * as github from '@actions/github'
import { env } from "process";
import { writeFile } from 'fs';
import * as auth from './auth'
import Axios from "axios";


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
    //check if workspace_autoamtion is set to true
    core.info('Check if workspace_autoamtion is set to true');
    if ( options.workspace_automation = true ) {
        core.info('workspace_autoamtion is set to ture, will run workspace_autoamtion');

        //set the platform region and base API url
        const cleanedID = options.VID?.replace('vera01ei-','') ?? '';
        const cleanedKEY = options.VKEY?.replace('vera01es-','') ?? '';
        const REPO_NAME = env.GITHUB_REPOSITORY ?? '';

        if ( options.VID?.startsWith('vera01ei-') ) {
            core.info('Platform is ER');
            var API_BASE_URL = 'https://api.veracode.eu';
        }
        else {
            core.info('Platform is US');
            var API_BASE_URL = 'https://api.veracode.com';
        }

        //check if workspace exists
        //var path = '/srcclr/v3/workspaces?filter%5Bworkspace%5D='+encodeURIComponent(REPO_NAME)
        var path = '/appsec/v1/applications?size=100&page=0&name='+encodeURIComponent(REPO_NAME)
        console.log('PATH: '+path)
        var checkWorkspace = await Axios.request({
            method: 'GET',
            headers:{
                'Authorization': auth.generateHeader(path, 'GET', API_BASE_URL, cleanedID, cleanedKEY),
            },
            url: API_BASE_URL+path
          });
          
          var workspaces = checkWorkspace.data._embedded.workspaces
          console.log(JSON.stringify(workspaces))


/*

        if ( worksapce == null ) {
            core.info('workspace doesn\'t exists and needs to be created');
            //create workspace
        }

        //check if agent already exists
        if ( agent == null ) {
            core.info('agent doesn\'t exists and needs to be created');
            //create agent
        }
        else {
            core.info('agent already exists, regenerat token');
        }

        //set token for the actual scan.

*/

    }
    else {
        core.info('workspace_autoamtion is set to false, will not run workspace_autoamtion');
    }



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
        extraCommands = `${extraCommands}${options.recursive?'--recursive ':''}${options.quick? '--quick ':''}${options.allowDirty? '--allow-dirty ':''}${options.updateAdvisor? '--update-advisor ':''}${skipVMS? '--skip-vms ':''}${noGraphs? '--no-graphs ':''}${options.debug? '--debug ':''}${skipCollectorsAttr}`;
        const command = `curl -sSL https://download.sourceclear.com/ci.sh | sh -s -- scan ${extraCommands} ${commandOutput}`;
        core.info(command);


        if (options.createIssues) {
            core.info('Starting the scan')
          const execution = spawn('sh',['-c',command],{
            stdio:"pipe",
            shell:false
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
            if (core.isDebug()){
                core.info(output);
            }

            //Pull request decoration
            core.info('check if we run on a pull request')
            let pullRequest = process.env.GITHUB_REF
            let isPR:any = pullRequest?.indexOf("pull")
            let summary_message = ""

            if ( isPR >= 1 ){
                core.info('We run on a PR, add more messaging')
                const context = github.context
                const repository:any = process.env.GITHUB_REPOSITORY
                const repo = repository.split("/");
                const commentID:any = context.payload.pull_request?.number
                let pr_header = '<br>![](https://www.veracode.com/themes/veracode_new/library/img/veracode-black-hires.svg)<br>'
                summary_message = `Veracode SCA Scan finished with exit code: ${code}. Please review created and linked issues`

                try {
                    const octokit = github.getOctokit(options.github_token);
        
                    const { data: comment } = await octokit.rest.issues.createComment({
                        owner: repo[0],
                        repo: repo[1],
                        issue_number: commentID,
                        body: pr_header+summary_message,
                    });
                    core.info('Adding scan results message as comment to PR #'+commentID)
                } catch (error:any) {
                    core.info(error);
                }
            }
            else {
                summary_message = `Veracode SCA Scan finished with exit code: ${code}. Please review created issues`
            }

            //Generate issues
            run(options,core.info);

            core.info(summary_message);
            // if scan was set to fail the pipeline should fail and show a summary of the scan results
            if ( code != null && code > 0 ){
                core.setFailed(summary_message)
            }

            //store output files as artifacts
            core.info('Store json Results as Artifact')
            const artifact = require('@actions/artifact');
            const artifactClient = artifact.create()
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

            const execution = spawn('sh',['-c',command],{
                stdio:"pipe",
                shell:false
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

                //write output to file
                writeFile('scaResults.txt', output, (err) => {
                    if (err) throw err;
                    console.log('The file has been saved!');
                });

                //store output files as artifacts
                core.info('Store json Results as Artifact')
                const artifact = require('@actions/artifact');
                const artifactClient = artifact.create()
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
                let isPR:any = pullRequest?.indexOf("pull")

                if ( isPR >= 1 ){
                    core.info("This run is part of a PR, should add some PR comment")
            
                    const context = github.context
                    const repository:any = process.env.GITHUB_REPOSITORY
                    const repo = repository.split("/");
                    const commentID:any = context.payload.pull_request?.number


                    let commentBody = '<br>![](https://www.veracode.com/themes/veracode_new/library/img/veracode-black-hires.svg)<br>'
                    commentBody += "Veraocde SCA Scan failed with exit code "+code+"\n"
                    commentBody += '\n<details><summary>Veracode SCA Scan details</summary><p>\n'
                    commentBody += output.replace(/    /g, '&nbsp;&nbsp;&nbsp;&nbsp;');
                    commentBody += '</p></details>\n'


                

                    try {
                        const octokit = github.getOctokit(options.github_token);
            
                        const { data: comment } = await octokit.rest.issues.createComment({
                            owner: repo[0],
                            repo: repo[1],
                            issue_number: commentID,
                            body: commentBody,
                        });
                        core.info('Adding scan results as comment to PR #'+commentID)
                    } catch (error:any) {
                        core.info(error);
                    }

                }




                // if scan was set to fail the pipeline should fail and show a summary of the scan results
                if ( code != null && code > 0 ){
                    let summary_info = "Veraocde SCA Scan failed with exit code "+code+"\n"+output
                    core.setFailed(summary_info)
                }
                //run(options,core.info);
                core.info('Finish command');
            });
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

