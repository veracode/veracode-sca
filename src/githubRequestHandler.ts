import {getOctokit,context} from '@actions/github';
import { VERACODE_LABEL,SEVERITY_LABELS } from './labels';
import { ReportedLibraryIssue } from './srcclr.d';

const ISSUES_PULL_COUNT = 100;

export class GithubHandler {

    private client:any;

    constructor(private token:string) {
        this.client = getOctokit(token); 
    }

    public async getVeracodeLabel ()  {
        console.log('getVeracodeLabel - START');
        let veracodeLabel:any = {};

        //we dont need a proxy for GitHub internal requests
        // Store current proxy environment variables
        const httpProxy = process.env.HTTP_PROXY
        const httpsProxy = process.env.HTTPS_PROXY
        const noProxy = process.env.NO_PROXY

        // Unset proxy environment variables
        delete process.env.HTTP_PROXY
        delete process.env.HTTPS_PROXY
        delete process.env.NO_PROXY


        try {
            
            veracodeLabel = await this.client.rest
                .issues.getLabel({
                    owner:context.repo.owner,
                    repo:context.repo.repo,
                    name:VERACODE_LABEL.name
            });
            console.log('Veracode Labels already exist');
        } catch (e) {
            console.log('=======================   ERROR   ===============================');
            console.log(e);    
        }

        // Restore proxy environment variables
        if (httpProxy) process.env.HTTP_PROXY = httpProxy
        if (httpsProxy) process.env.HTTPS_PROXY = httpsProxy
        if (noProxy) process.env.NO_PROXY = noProxy


        console.log('getVeracodeLabel - END');
        return veracodeLabel;
    }

    public async createVeracodeLabels() {
        console.log('createVeracodeLabels - END');
        try {
            // Creating the severity labels
            for (var label of Object.values(SEVERITY_LABELS)) {
              await this.client.rest.issues.createLabel({
                    owner:context.repo.owner,
                    repo:context.repo.repo,
                    name: label.name,
                    color: label.color,
                    description: label.description
                });
            }

            //we dont need a proxy for GitHub internal requests
            // Store current proxy environment variables
            const httpProxy = process.env.HTTP_PROXY
            const httpsProxy = process.env.HTTPS_PROXY
            const noProxy = process.env.NO_PROXY

            // Unset proxy environment variables
            delete process.env.HTTP_PROXY
            delete process.env.HTTPS_PROXY
            delete process.env.NO_PROXY

            // Creating the base label
            await this.client.rest.issues.createLabel({
                owner:context.repo.owner,
                repo:context.repo.repo,
                name: VERACODE_LABEL.name,
                color: VERACODE_LABEL.color,
                description: VERACODE_LABEL.description
            });

             // Restore proxy environment variables
            if (httpProxy) process.env.HTTP_PROXY = httpProxy
            if (httpsProxy) process.env.HTTPS_PROXY = httpsProxy
            if (noProxy) process.env.NO_PROXY = noProxy

            //this.client.paginate(this.client.graphql,"");
    
        } catch (e) {
            console.log('=======================   ERROR   ===============================');
            console.log(e);
        }
        console.log('createVeracodeLabels - END');
    }

    public async createIssue(reportedIssue: ReportedLibraryIssue) {

        //we dont need a proxy for GitHub internal requests
        // Store current proxy environment variables
        const httpProxy = process.env.HTTP_PROXY
        const httpsProxy = process.env.HTTPS_PROXY
        const noProxy = process.env.NO_PROXY

        // Unset proxy environment variables
        delete process.env.HTTP_PROXY
        delete process.env.HTTPS_PROXY
        delete process.env.NO_PROXY

        return await this.client.rest.issues.create({
            owner:context.repo.owner,
            repo:context.repo.repo,
            title:reportedIssue.title,
            body:reportedIssue.description,
            labels: reportedIssue.labels
        });

         // Restore proxy environment variables
         if (httpProxy) process.env.HTTP_PROXY = httpProxy
         if (httpsProxy) process.env.HTTPS_PROXY = httpsProxy
         if (noProxy) process.env.NO_PROXY = noProxy
    }

    public async listExistingOpenIssues() {
        console.log('getIssues - START');
        const query = `query IsslesTitle($organization: String!,$repo: String!, $count: Int!,$label: String!) {
            repository(name: $repo, owner: $organization) {
              issues(first: $count,filterBy: {labels: [$label], states: OPEN}) {
                edges {
                  node {
                    title
                    number
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }`;

        const nextQuery = `query IsslesTitle($organization: String!,$repo: String!, $count: Int!, $endCursor: String!,$label: String!) {
            repository(name: $repo, owner: $organization) {
              issues(first: $count,after: $endCursor,filterBy: {labels: [$label], states: OPEN}) {
                edges {
                  node {
                    title
                    number
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }`;
        
        let issues:Array<{
            node: {
                title: string,
                number: number
            }
        }> = [];


        //we dont need a proxy for the artifact upload
        // Store current proxy environment variables
        const HTTP_PROXY = process.env.HTTP_PROXY
        const HTTPS_PROXY = process.env.HTTPS_PROXY
        const NO_PROXY = process.env.NO_PROXY
        const http_proxy = process.env.http_proxy
        const https_proxy = process.env.https_proxy
        const no_proxy = process.env.no_proxy

        // Unset proxy environment variables
        delete process.env.HTTP_PROXY
        delete process.env.HTTPS_PROXY
        delete process.env.NO_PROXY
        delete process.env.http_proxy
        delete process.env.https_proxy
        delete process.env.no_proxy

        try {
            let issuesRes: any = await this.client.graphql({
                headers: {
                    authorization: `token ${this.token}`
                },
                query,
                count: ISSUES_PULL_COUNT,
                organization: context.repo.owner,
                repo: context.repo.repo,
                label: VERACODE_LABEL.name
            });
             
            issues = issues.concat(issuesRes.repository.issues.edges);

            while (issuesRes.repository.issues.pageInfo.hasNextPage) {
                console.log('iterating for fetching more related open issues')
                const endCursor =issuesRes.repository.issues.pageInfo.endCursor;

                issuesRes = await this.client.graphql({
                    headers: {
                        authorization: `token ${this.token}`
                    },
                    query:nextQuery,
                    count: ISSUES_PULL_COUNT,
                    endCursor,
                    organization: context.repo.owner,
                    repo: context.repo.repo,
                    label: VERACODE_LABEL.name
                });
                issues = issues.concat(issuesRes.repository.issues.edges);
            }
        } catch (e) {
                console.log('=======================   ERROR   ===============================');
                console.log(e);
        }

        // Restore proxy environment variables
        if (HTTP_PROXY) process.env.HTTP_PROXY = HTTP_PROXY
        if (HTTPS_PROXY) process.env.HTTPS_PROXY = HTTPS_PROXY
        if (NO_PROXY) process.env.NO_PROXY = NO_PROXY
        if (http_proxy) process.env.http_proxy = http_proxy
        if (https_proxy) process.env.https_proxy = https_proxy
        if (no_proxy) process.env.no_proxy = no_proxy

        console.log('getIssues - END');
        return issues;
    }
}

