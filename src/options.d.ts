export interface Options {
    quick: boolean,
    updateAdvisor: boolean,
    minCVSSForIssue: number,
    url: string,
    github_token: string,
    createIssues: boolean,
    failOnCVSS: number,
    path: string,
    debug: boolean,
    allowDirty:boolean,
    recursive:boolean,
    "skip-vms":boolean,
    "no-graphs":boolean,
    "skip-collectors": Array<string>,
    artifactname: string
}


