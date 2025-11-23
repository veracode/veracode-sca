//import {getOctokit,context} from '@actions/github';
import { readFileSync, existsSync, writeFileSync} from 'fs';
import { Options } from './options';
import { LibraryIssuesCollection, ReportedLibraryIssue, SCALibrary, SCAVulnerability, SrcClrJson } from './srcclr.d';
import { Label, SEVERITY_LABELS, VERACODE_LABEL } from './labels';
import { GithubHandler } from './githubRequestHandler';
import * as core from '@actions/core'

const { request } = require('@octokit/request');
const github = require('@actions/github');

export const SCA_OUTPUT_FILE = 'scaResults.json';

const librariesWithIssues:any = {};

let githubHandler: GithubHandler;

export async function run(options:Options, msgFunc: (msg: string) => void) {

    if (!existsSync(SCA_OUTPUT_FILE)) {
        core.setFailed('SCA Output file was not found - cannot proceed with creating issues.\nPlease check prior execution errors.');
        return;
    }

    const scaResultsTxt = readFileSync(SCA_OUTPUT_FILE);  

    const scaResJson: SrcClrJson = JSON.parse(scaResultsTxt.toString('utf-8'));

    const vulnerabilities = scaResJson.records[0].vulnerabilities;
    const libraries = scaResJson.records[0].libraries;

    vulnerabilities
        //.filter((vul:any) => vul.cvssScore>=options.minCVSSForIssue)
        .forEach((vulr) => {
            //console.log('-------   in each   ------');
            const libref = vulr.libraries[0]._links.ref;
            //core.info('libref: '+libref)
            const libId = libref.split('/')[4];
            //core.info('libId: '+libId)
            const lib:SCALibrary = libraries[libId];
            //core.info('lib: '+JSON.stringify(lib))
            const details = createIssueDetails(vulr,lib);
            addIssueToLibrary(libId,lib,details);
        });

    githubHandler = new GithubHandler(options.github_token, options.owner, options.repo);

    if (Object.keys(librariesWithIssues).length>0) {
        await verifyLabels();
        await syncExistingOpenIssues(options);

        // check for failing the step
        /*
        const failingVul = vulnerabilities.filter(vul => vul.cvssScore>=options.failOnCVSS);
        if (failingVul.length>0) {
            core.setFailed(`Found Vulnerability with CVSS equal or greater than ${options.failOnCVSS}`);
        } else {
            msgFunc(`No 3rd party library found with Vulnerability of CVSS equal or greater than ${options.failOnCVSS}`);
        }
        */
    }

    // Generate and submit dependency snapshot for Dependabot alerts if enabled
    if (options.dependabot_alerts) {
        core.info('Generating dependency snapshot for Dependabot alerts');
        try {
            await submitDependencySnapshot(options, scaResJson);
            core.info('Successfully submitted dependency snapshot to GitHub');
        } catch (error: any) {
            core.warning(`Failed to submit dependency snapshot: ${error.message}`);
            if (options.debug) {
                core.info(`Error details: ${JSON.stringify(error)}`);
            }
        }
    }

    msgFunc(`Scan finished.\nFull Report Details:   ${scaResJson.records[0].metadata.report}`);
}

const addIssueToLibrary = (libId:string,lib:SCALibrary,details:ReportedLibraryIssue) => {
    let libWithIssues: LibraryIssuesCollection = librariesWithIssues[libId] || {lib,issues:[]};
    libWithIssues.issues.push(details);
    librariesWithIssues[libId] = libWithIssues;
}

const syncExistingOpenIssues = async (options:any) => {
    const existingOpenIssues = await githubHandler.listExistingOpenIssues();

    const lenghtOfLibs = Object.keys(librariesWithIssues).length
    core.info('Libraries with issues found: '+lenghtOfLibs)

    let createIssue
    let openIssueTitle
    let openIssueNumber

    //Check if we run on a PR
    core.info('check if we run on a pull request')
    let pullRequest = process.env.GITHUB_REF
    let isPR:any = pullRequest?.indexOf("pull")

    for (var key in librariesWithIssues) {
        core.info('Library '+key+' - '+librariesWithIssues[key]['lib']['name'])

        var issueLength = Object.keys(librariesWithIssues[key]['issues']).length
        core.info(issueLength+' Issues found on Library')


        for ( let j=0; j< issueLength; j++ ){
            var libraryTitle = librariesWithIssues[key]['issues'][j]['title']
            core.info('Isuse Title '+j+': '+libraryTitle)
            var openIssueLenght = existingOpenIssues.length
            core.info("Open issues found: "+openIssueLenght)
            for (let k = 0; k < openIssueLenght; k++){
                openIssueTitle = existingOpenIssues[k]['node']['title']
                openIssueNumber = existingOpenIssues[k]['node']['number']
                //core.info('Open Isssue: '+openIssueTitle+' --- '+openIssueNumber)

                if ( libraryTitle == openIssueTitle ){
                    core.info('Issue \n'+libraryTitle+'\n'+openIssueTitle+'\nalready exists - skipping')
                    createIssue = false
                    break
                }
            }
            if ( createIssue == false ){
                core.info('Issue already exists - skipping  --- '+libraryTitle+' ---- '+openIssueTitle)
                if ( isPR >= 1 ){
                    core.info('We run on a PR, link issue to PR')
                    let pr_context = github.context
                    let pr_commentID = pr_context.payload.pull_request.number

                    var authToken = 'token ' + options.github_token

                    const owner = options.owner;
                    const repo = options.repo;
                    var pr_link = `Veracode issue link to PR: https://github.com/`+owner+`/`+repo+`/pull/`+pr_commentID

                    console.log('Adding PR to the issue now.')
                        
                    await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                        headers: {
                            authorization: authToken
                        },
                        owner: owner,
                        repo: repo,
                        issue_number: openIssueNumber,
                        data: {
                            "body": pr_link
                        }
                    })
                }
            }
            else {
                core.info('Issue needs to be created. --- '+libraryTitle)
                const ghResponse = await githubHandler.createIssue(librariesWithIssues[key]['issues'][j]);
                //core.info('Issue creation response: '+JSON.stringify(ghResponse))
                var issueNumber = ghResponse.data.number
                if ( isPR >= 1 ){
                    core.info('We run on a PR, link issue to PR')
                    let pr_context = github.context
                    let pr_commentID = pr_context.payload.pull_request.number

                    var authToken = 'token ' + options.github_token

                    const owner = options.owner;
                    const repo = options.repo;
                    var pr_link = `Veracode issue link to PR: https://github.com/`+owner+`/`+repo+`/pull/`+pr_commentID

                    console.log('Adding PR to the issue now.')
                        
                    await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                        headers: {
                            authorization: authToken
                        },
                        owner: owner,
                        repo: repo,
                        issue_number: issueNumber,
                        data: {
                            "body": pr_link
                        }
                    })
                }
            }
        }
    }
}

const createIssueDetails = (vuln: SCAVulnerability,lib: SCALibrary): ReportedLibraryIssue => {
    const vulnLibDetails = vuln.libraries[0].details[0];
    const sevLabel = getSeverityName(vuln.cvssScore);
    const myCVE = vuln.cve || '0000-0000';
    const versionsFound = lib.versions.map(version => version.version);
    var title = "CVE: "+myCVE+" found in "+lib.name+" - Version: "+versionsFound+" ["+vuln.language+"]";
    var labels: Array<Label> = [VERACODE_LABEL,sevLabel];
    var description = "Veracode Software Composition Analysis"+
        "  \n===============================\n"+
        "  \n Attribute | Details"+
        "  \n| --- | --- |"+
        "  \nLibrary | "+lib.name+
        "  \nDescription | "+lib.description+
        "  \nLanguage | "+vuln.language+
        "  \nVulnerability | "+vuln.title+
        "  \nVulnerability description | "+(vuln.overview ? vuln.overview.trim() : "")+
        "  \nCVE | "+vuln.cve+
        "  \nCVSS score | "+vuln.cvssScore+
        "  \nVulnerability present in version/s | "+vulnLibDetails.versionRange+
        "  \nFound library version/s | "+versionsFound+
        "  \nVulnerability fixed in version | "+vulnLibDetails.updateToVersion+
        "  \nLibrary latest version | "+lib.latestRelease+
        "  \nFix | "+vulnLibDetails.fixText+
        "  \n"+
        "  \nLinks:"+
        "  \n- "+lib.versions[0]._links.html+
        "  \n- "+vuln._links.html+
        "  \n- Patch: "+vulnLibDetails.patch;

    return {
        title,description,labels
    };
}

const getSeverityName = (cvss: number):Label => {
    var weight = Math.floor(cvss);
    let label = SEVERITY_LABELS.Unknown;
    if (weight == 0)
        label = SEVERITY_LABELS.Informational;
    else if (weight >= 0.1 && weight < 1.9)
        label =  SEVERITY_LABELS['Very Low'];
    else if (weight >= 2.0 && weight < 3.9)
        label = SEVERITY_LABELS.Low;
    else if (weight >= 4.0 && weight < 5.9)
        label = SEVERITY_LABELS.Medium;
    else if (weight >= 6.0 && weight < 7.9)
        label = SEVERITY_LABELS.High;
    else if (weight >= 8.0)
        label = SEVERITY_LABELS['Very High'];

    return label;
}

const verifyLabels = async () => {
    const baseLabel = await githubHandler.getVeracodeLabel();
    
    if (!baseLabel || !baseLabel.data) {
        await githubHandler.createVeracodeLabels();
    }
}

export async function runText(options:Options,output:string, msgFunc: (msg: string) => void) {
    const vulnerabilityLinePattern: RegExp = /^\d+\s+Vulnerability\s+([\d\.]+)\s+.+/; 
    const splitLines:string[] = output.split(/\r?\n/);
    let failed: boolean = false;
    for (var line of splitLines) {
        if (vulnerabilityLinePattern.test(line)) {
            const match = line.match(vulnerabilityLinePattern);
            if (match) {
                const cvss = parseFloat(match[1]);
                if (cvss>=options.failOnCVSS) {
                    failed = true;
                }
            }
        }
    }

    if (failed) {
        core.setFailed(`Found Vulnerability with CVSS equal or greater than ${options.failOnCVSS}`);
    } else {
        msgFunc(`No 3rd party library found with Vulnerability of CVSS equal or greater than ${options.failOnCVSS}`);
    }
}

/**
 * Converts Veracode SCA library information to Package URL (purl) format
 */
function generatePackageUrl(lib: SCALibrary, version: string, language: string): string {
    const name = lib.name.toLowerCase().replace(/[^a-z0-9._-]/g, '');
    const ver = version || 'unknown';
    
    // Map language to purl type
    const typeMap: { [key: string]: string } = {
        'javascript': 'npm',
        'java': 'maven',
        'python': 'pypi',
        'ruby': 'gem',
        'php': 'composer',
        'go': 'golang',
        'rust': 'cargo',
        'dotnet': 'nuget',
        'swift': 'swift',
        'objective-c': 'cocoapods'
    };
    
    const purlType = typeMap[language.toLowerCase()] || 'generic';
    
    // Handle Maven coordinates if available
    if (purlType === 'maven' && lib.coordinate1 && lib.coordinate2) {
        const groupId = lib.coordinate1.replace(/[^a-z0-9._-]/gi, '');
        const artifactId = lib.coordinate2.replace(/[^a-z0-9._-]/gi, '');
        return `pkg:maven/${groupId}/${artifactId}@${ver}`;
    }
    
    return `pkg:${purlType}/${name}@${ver}`;
}

/**
 * Generates a GitHub dependency snapshot from Veracode SCA results
 * Returns null if no libraries are found
 */
function generateDependencySnapshot(scaResJson: SrcClrJson): any | null {
    const context = github.context;
    const sha = context.sha || process.env.GITHUB_SHA || '';
    const ref = context.ref || process.env.GITHUB_REF || 'refs/heads/main';
    
    // Generate job ID and correlator for the snapshot
    // Correlator should be unique per workflow run, job ID should be unique per job
    const workflowRunId = process.env.GITHUB_RUN_ID || '';
    const jobId = process.env.GITHUB_JOB || 'veracode-sca';
    const correlator = `veracode-sca-${workflowRunId}-${jobId}`;
    
    const libraries = scaResJson.records[0].libraries;
    const vulnerabilities = scaResJson.records[0].vulnerabilities;
    
    // Group libraries by language/manifest
    const manifests: { [key: string]: any } = {};
    
    // Process all libraries
    const totalLibraries = Object.keys(libraries).length;
    core.info(`Processing ${totalLibraries} libraries from Veracode SCA scan`);
    
    for (const libId in libraries) {
        const lib: SCALibrary = libraries[libId];
        
        // Debug: Log library being processed
        if (core.isDebug()) {
            core.info(`Processing library: ${lib.name} (ID: ${libId})`);
            core.info(`  - Coordinate1: ${lib.coordinate1 || 'N/A'}, Coordinate2: ${lib.coordinate2 || 'N/A'}`);
            core.info(`  - Versions: ${lib.versions.map(v => v.version).join(', ')}`);
        }
        
        // Find vulnerabilities for this library to determine language
        let language = 'generic';
        let foundLanguage = false;
        for (const vuln of vulnerabilities) {
            const libref = vuln.libraries[0]._links.ref;
            const vulnLibId = libref.split('/')[4];
            if (vulnLibId === libId) {
                language = (vuln.language && vuln.language.trim()) || 'generic';
                foundLanguage = true;
                if (core.isDebug()) {
                    core.info(`  - Found language from vulnerability: ${language}`);
                }
                break;
            }
        }
        
        // If no vulnerability found for this library, try to infer language from library name/coordinates
        if (!foundLanguage) {
            // Try to infer from Maven coordinates
            if (lib.coordinate1 && lib.coordinate2) {
                language = 'java';
                if (core.isDebug()) {
                    core.info(`  - Inferred language 'java' from Maven coordinates`);
                }
            } else {
                // Check library name for common patterns
                const libNameLower = lib.name.toLowerCase();
                if (libNameLower.includes('package.json') || libNameLower.includes('node_modules') || libNameLower.includes('npm')) {
                    language = 'javascript';
                } else if (libNameLower.includes('requirements') || libNameLower.includes('pip') || libNameLower.includes('python')) {
                    language = 'python';
                } else if (libNameLower.includes('gem') || libNameLower.includes('ruby')) {
                    language = 'ruby';
                } else if (libNameLower.includes('composer') || libNameLower.includes('php')) {
                    language = 'php';
                } else if (libNameLower.includes('go.mod') || libNameLower.includes('golang')) {
                    language = 'go';
                } else {
                    language = 'generic';
                }
                if (core.isDebug()) {
                    core.info(`  - Inferred language '${language}' from library name/pattern`);
                }
            }
        }
        
        // Ensure language is never empty
        if (!language || language.trim() === '') {
            language = 'generic';
        }
        
        // Create manifest key based on language
        const manifestKey = `veracode-${language.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
        
        if (!manifests[manifestKey]) {
            // Ensure name is never blank - use a descriptive name
            const manifestName = `Veracode SCA - ${language.charAt(0).toUpperCase() + language.slice(1)}`;
            // Use a distinct file path that identifies this as Veracode SCA submission
            // Using a path format that GitHub recognizes for dependency submission
            // The path should be relative to repository root
            const timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
            const manifestFilePath = `.github/veracode-sca/${language.toLowerCase()}-${timestamp}.json`;
            manifests[manifestKey] = {
                name: manifestName,
                file: {
                    source_location: manifestFilePath
                },
                resolved: {}
            };
            if (core.isDebug()) {
                core.info(`Created new manifest: ${manifestKey} -> ${manifestFilePath}`);
            }
        }
        
        // Add each version of the library
        for (const versionInfo of lib.versions) {
            const purl = generatePackageUrl(lib, versionInfo.version, language);
            // Use a simpler key that's valid for JSON
            const purlKey = Buffer.from(purl).toString('base64').replace(/[+/=]/g, '_');
            
            if (core.isDebug()) {
                core.info(`  - Adding dependency: ${lib.name}@${versionInfo.version} -> ${purl}`);
            }
            
            manifests[manifestKey].resolved[purlKey] = {
                package_url: purl,
                dependencies: []
            };
        }
    }
    
    // Debug: Log summary of processed libraries
    core.info(`Processed ${totalLibraries} libraries into ${Object.keys(manifests).length} manifest(s)`);
    for (const manifestKey in manifests) {
        const depCount = Object.keys(manifests[manifestKey].resolved).length;
        core.info(`  - ${manifestKey}: ${depCount} dependencies`);
    }
    
    // Ensure all manifests have valid names and at least one has dependencies
    // If no libraries found, we shouldn't submit an empty snapshot
    // But if we have manifests, ensure they all have proper names
    for (const manifestKey in manifests) {
        const manifest = manifests[manifestKey];
        if (!manifest.name || manifest.name.trim() === '') {
            manifest.name = `Veracode SCA - ${manifestKey.replace('veracode-', '').charAt(0).toUpperCase() + manifestKey.replace('veracode-', '').slice(1)}`;
        }
    }
    
    // If no libraries found, don't create an empty manifest
    // GitHub requires at least one dependency in the snapshot
    if (Object.keys(manifests).length === 0) {
        core.warning('No libraries found in SCA results - skipping dependency snapshot submission');
        return null;
    }
    
    const snapshot = {
        version: 0,
        sha: sha,
        ref: ref,
        job: {
            id: jobId,
            correlator: correlator
        },
        detector: {
            name: 'veracode-sca',
            version: '1.0.8',
            url: 'https://github.com/veracode/veracode-sca'
        },
        scanned: new Date().toISOString(),
        manifests: manifests
    };
    
    return snapshot;
}

/**
 * Submits dependency snapshot to GitHub Dependency Submission API from file
 */
export async function submitDependencySnapshotFromFile(options: Options): Promise<void> {
    if (!existsSync(SCA_OUTPUT_FILE)) {
        core.warning('SCA Output file was not found - cannot submit dependency snapshot.');
        return;
    }

    const scaResultsTxt = readFileSync(SCA_OUTPUT_FILE);  
    const scaResJson: SrcClrJson = JSON.parse(scaResultsTxt.toString('utf-8'));
    await submitDependencySnapshot(options, scaResJson);
}


/**
 * Submits dependency snapshot to GitHub Dependency Submission API
 */
async function submitDependencySnapshot(options: Options, scaResJson: SrcClrJson): Promise<void> {
    const owner = options.owner;
    const repo = options.repo;
    
    const snapshot = generateDependencySnapshot(scaResJson);
    
    // If no snapshot was generated (no libraries found), skip submission
    if (!snapshot) {
        core.info('No dependency snapshot generated - no libraries found in scan results');
        return;
    }
    
    // Save snapshot to file for artifact upload
    const snapshotFileName = 'dependabot-snapshot.json';
    try {
        writeFileSync(snapshotFileName, JSON.stringify(snapshot, null, 2));
        core.info(`Saved dependency snapshot to ${snapshotFileName}`);
    } catch (error: any) {
        core.warning(`Failed to save snapshot file: ${error.message}`);
    }
    
    if (options.debug) {
        core.info(`Dependency snapshot: ${JSON.stringify(snapshot, null, 2)}`);
        core.info(`Manifests in snapshot: ${Object.keys(snapshot.manifests).join(', ')}`);
        for (const manifestKey in snapshot.manifests) {
            const manifest = snapshot.manifests[manifestKey];
            const depCount = Object.keys(manifest.resolved || {}).length;
            core.info(`  - ${manifestKey}: ${manifest.name} (${depCount} dependencies) from ${manifest.file.source_location}`);
            
            // Debug: List all package URLs in this manifest
            if (core.isDebug()) {
                core.info(`    Package URLs in ${manifestKey}:`);
                for (const purlKey in manifest.resolved) {
                    const dep = manifest.resolved[purlKey];
                    core.info(`      - ${dep.package_url}`);
                }
            }
        }
    }
    
    const authToken = `token ${options.github_token}`;
    
    try {
        const response = await request('POST /repos/{owner}/{repo}/dependency-graph/snapshots', {
            headers: {
                authorization: authToken,
                accept: 'application/vnd.github+json',
                'content-type': 'application/json'
            },
            owner: owner,
            repo: repo,
            data: snapshot
        });
        
        core.info(`Dependency snapshot submitted successfully. Response status: ${response.status}`);
        core.info(`Submitted ${Object.keys(snapshot.manifests).length} manifest(s) with dependencies from Veracode SCA scan`);
        
        // Log manifest details for debugging
        for (const manifestKey in snapshot.manifests) {
            const manifest = snapshot.manifests[manifestKey];
            const depCount = Object.keys(manifest.resolved || {}).length;
            core.info(`  Manifest: ${manifest.name} (${depCount} dependencies) - File: ${manifest.file.source_location}`);
            
            // Check for specific libraries like "nocivo"
            const allPackageUrls: string[] = [];
            for (const purlKey in manifest.resolved) {
                allPackageUrls.push(manifest.resolved[purlKey].package_url);
            }
            const nocivoDeps = allPackageUrls.filter(url => url.toLowerCase().includes('nocivo'));
            if (nocivoDeps.length > 0) {
                core.info(`    Found ${nocivoDeps.length} nocivo dependency(ies): ${nocivoDeps.join(', ')}`);
            }
        }
        
        // Upload snapshot as artifact
        try {
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
            const artifactName = 'Veracode Dependabot Snapshot';
            const files = [snapshotFileName];
            const rootDirectory = process.cwd();
            const artefactOptions = {
                continueOnError: true
            };

            const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, artefactOptions);
            core.info(`Uploaded dependency snapshot as artifact: ${artifactName}`);
        } catch (artifactError: any) {
            core.warning(`Failed to upload snapshot as artifact: ${artifactError.message}`);
        }
        
        core.info(`Note: Dependencies are merged with GitHub's native dependency graph. ` +
                  `If dependencies are already detected by native scanning (e.g., from pom.xml), ` +
                  `they will appear under the native manifest, not as a separate Veracode manifest. ` +
                  `Only unique dependencies or vulnerabilities will appear under the Veracode manifest.`);
    } catch (error: any) {
        if (error.status === 403) {
            throw new Error('Permission denied. Ensure the token has write access to dependency graph. Dependabot alerts must be enabled for the repository.');
        } else if (error.status === 422) {
            throw new Error(`Invalid snapshot format: ${error.message}. Check the dependency snapshot structure.`);
        } else {
            throw new Error(`Failed to submit dependency snapshot: ${error.message}`);
        }
    }
}
